# Read only. For the named feature check functions inside a driver, finds the functions that call them (E8 rel32 call sites), then lists every call made by each such caller, resolving direct calls through the public symbols of the PDB and import calls (FF 15) through the import table. Gives the decision logic around a feature flag without a disassembler.
param(
    [string]$Binary = 'storport.sys',
    [string]$Pdb = 'C:\Temp\claude\C--Users-Rev-Oconner-terminal-temp\0e176570-1dcc-481e-aee1-e01d7557119e\scratchpad\symbols\CFD59EEA80EE43ACE6BF72940618B9901_storport.pdb',
    [string[]]$Targets = @('Feature_NativeNVMeStackForGeClient__private_IsEnabledDeviceUsageNoInline', 'Feature_NativeNVMeStackForGeClient__private_IsEnabledFallback', 'Feature_NativeNVMeStackForGeServer__private_IsEnabledDeviceUsageNoInline', 'Feature_NativeNVMeStackForGeServer__private_IsEnabledFallback', 'Feature_Servicing_NativeNVMe__private_IsEnabledDeviceUsageNoInline', 'Feature_Servicing_NativeNVMe__private_IsEnabledFallback'),
    [int]$MaxCallsPerFunction = 80
)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public class PeMap
{
    public byte[] B;
    public ulong ImageBase;
    public List<uint[]> Sections = new List<uint[]>();
    public uint TextRva, TextSize;
    public Dictionary<uint, string> Imports = new Dictionary<uint, string>();
    public PeMap(string path)
    {
        B = File.ReadAllBytes(path);
        int e = BitConverter.ToInt32(B, 0x3C);
        int opt = e + 24;
        bool plus = BitConverter.ToUInt16(B, opt) == 0x20b;
        ImageBase = plus ? BitConverter.ToUInt64(B, opt + 24) : BitConverter.ToUInt32(B, opt + 28);
        ushort nsec = BitConverter.ToUInt16(B, e + 6);
        ushort optsz = BitConverter.ToUInt16(B, e + 20);
        int sh = opt + optsz;
        for (int i = 0; i < nsec; i++)
        {
            int o = sh + i * 40;
            string n = Encoding.ASCII.GetString(B, o, 8).TrimEnd('\0');
            var s = new uint[] { BitConverter.ToUInt32(B, o + 12), BitConverter.ToUInt32(B, o + 8), BitConverter.ToUInt32(B, o + 20), BitConverter.ToUInt32(B, o + 16) };
            Sections.Add(s);
            if (n == ".text") { TextRva = s[0]; TextSize = s[3]; }
        }
        int dd = opt + (plus ? 112 : 96);
        uint impRva = BitConverter.ToUInt32(B, dd + 8);
        long imp = RvaToOff(impRva);
        for (int d = 0; ; d += 20)
        {
            uint oft = BitConverter.ToUInt32(B, (int)imp + d), nameRva = BitConverter.ToUInt32(B, (int)imp + d + 12), ft = BitConverter.ToUInt32(B, (int)imp + d + 16);
            if (nameRva == 0) break;
            string dll = ReadAscii(RvaToOff(nameRva));
            long intOff = RvaToOff(oft == 0 ? ft : oft);
            for (int k = 0; ; k += 8)
            {
                ulong ent = BitConverter.ToUInt64(B, (int)intOff + k);
                if (ent == 0) break;
                string fn = (ent & 0x8000000000000000UL) != 0 ? "ordinal" + (ent & 0xFFFF) : ReadAscii(RvaToOff((uint)ent) + 2);
                Imports[(uint)(ft + k)] = dll + "!" + fn;
            }
        }
    }
    string ReadAscii(long off) { if (off < 0) return "?"; int l = 0; while (off + l < B.Length && B[off + l] != 0 && l < 200) l++; return Encoding.ASCII.GetString(B, (int)off, l); }
    public long RvaToOff(uint rva) { foreach (var s in Sections) { if (rva >= s[0] && rva < s[0] + Math.Max(s[1], s[3])) return rva - s[0] + s[2]; } return -1; }
    public long OffToRva(long off) { foreach (var s in Sections) { if (off >= s[2] && off < s[2] + s[3]) return off - s[2] + s[0]; } return -1; }
    public long SegOffToRva(int seg, uint off) { if (seg < 1 || seg > Sections.Count) return -1; return Sections[seg - 1][0] + off; }

    // returns "callerRva|siteRva" for every E8 call whose target is targetRva
    public List<long> CallSites(uint targetRva)
    {
        var res = new List<long>();
        long t0 = RvaToOff(TextRva);
        for (long i = t0; i < t0 + TextSize - 5; i++)
        {
            if (B[i] != 0xE8) continue;
            int rel = BitConverter.ToInt32(B, (int)i + 1);
            long site = OffToRva(i);
            if (site + 5 + rel == targetRva) res.Add(site);
        }
        return res;
    }
    // every call inside [startRva, endRva): "siteRva|kind|targetRva"
    public List<string> CallsIn(uint startRva, uint endRva)
    {
        var res = new List<string>();
        long a = RvaToOff(startRva), z = RvaToOff(endRva);
        for (long i = a; i < z - 5; i++)
        {
            if (B[i] == 0xE8) { int rel = BitConverter.ToInt32(B, (int)i + 1); long s = OffToRva(i); long t = s + 5 + rel; if (t >= TextRva && t < TextRva + TextSize) res.Add(s + "|E8|" + t); }
            else if (B[i] == 0xFF && B[i + 1] == 0x15) { int rel = BitConverter.ToInt32(B, (int)i + 2); long s = OffToRva(i); long t = s + 6 + rel; if (Imports.ContainsKey((uint)t)) res.Add(s + "|IAT|" + t); }
        }
        return res;
    }
}

public static class PdbPub
{
    public static List<string> All(string pdb)
    {
        var res = new List<string>();
        byte[] b = File.ReadAllBytes(pdb);
        for (int i = 2; i + 14 < b.Length; i++)
        {
            if (b[i] != 0x0E || b[i + 1] != 0x11) continue;
            int len = BitConverter.ToUInt16(b, i - 2);
            if (len < 14 || len > 600) continue;
            uint off = BitConverter.ToUInt32(b, i + 6);
            int seg = BitConverter.ToUInt16(b, i + 10);
            if (seg < 1 || seg > 32) continue;
            int n = i + 12; int l = 0;
            while (n + l < b.Length && b[n + l] != 0 && l < 500) { byte c = b[n + l]; if (c < 0x20 || c > 0x7E) { l = -1; break; } l++; }
            if (l < 2) continue;
            res.Add(seg + "|" + off + "|" + Encoding.ASCII.GetString(b, n, l));
        }
        return res;
    }
}
'@

$pe = New-Object PeMap((Join-Path $env:SystemRoot "System32\drivers\$Binary"))
$syms = New-Object System.Collections.ArrayList
$byName = @{}
foreach ($s in [PdbPub]::All($Pdb)) {
    $p = $s.Split('|', 3); $rva = $pe.SegOffToRva([int]$p[0], [uint32]$p[1])
    if ($rva -lt 0) { continue }
    [void]$syms.Add([pscustomobject]@{ Rva = [long]$rva; Name = $p[2] })
    if (-not $byName.ContainsKey($p[2])) { $byName[$p[2]] = [long]$rva }
}
$sorted = @($syms | Sort-Object Rva -Unique)
$rvas = [long[]]($sorted | ForEach-Object { $_.Rva })
function SymAt([long]$rva) {
    $idx = [Array]::BinarySearch($rvas, $rva); if ($idx -lt 0) { $idx = (-bnot $idx) - 1 }
    if ($idx -lt 0) { return $null }
    [pscustomobject]@{ Name = $sorted[$idx].Name; Start = $sorted[$idx].Rva; End = $(if ($idx + 1 -lt $sorted.Count) { $sorted[$idx + 1].Rva } else { $sorted[$idx].Rva + 0x1000 }) }
}
"symbols mapped: $($sorted.Count)   imports: $($pe.Imports.Count)   .text rva 0x{0:X} size 0x{1:X}" -f $pe.TextRva, $pe.TextSize

$callers = @{}
foreach ($t in $Targets) {
    if (-not $byName.ContainsKey($t)) { "== $t : symbol not found"; continue }
    $trva = $byName[$t]
    $sites = $pe.CallSites([uint32]$trva)
    "== {0} at rva 0x{1:X}: {2} call sites" -f $t, $trva, $sites.Count
    foreach ($site in $sites) {
        $f = SymAt $site
        "   called from {0} +0x{1:X}" -f $f.Name, ($site - $f.Start)
        $callers[$f.Name] = $f
    }
}

foreach ($name in ($callers.Keys | Sort-Object)) {
    $f = $callers[$name]
    ""
    "#### {0}  rva 0x{1:X} to 0x{2:X}  ({3} bytes), calls in order:" -f $name, $f.Start, $f.End, ($f.End - $f.Start)
    $calls = $pe.CallsIn([uint32]$f.Start, [uint32]$f.End)
    $n = 0
    foreach ($c in $calls) {
        $p = $c.Split('|'); $site = [long]$p[0]; $t = [long]$p[2]
        $label = if ($p[1] -eq 'IAT') { $pe.Imports[[uint32]$t] } else { $x = SymAt $t; if ($x -and $x.Start -eq $t) { $x.Name } else { 'sub_{0:X}' -f $t } }
        "   +0x{0:X4}  {1}" -f ($site - $f.Start), $label
        if (++$n -ge $MaxCallsPerFunction) { "   ... truncated"; break }
    }
}
