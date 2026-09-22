# Read only. Finds every rip relative reference to the two byte globals that storport.sys DllInitialize fills from the NVMe feature checks, names the functions that read them, and lists the calls those functions make. Also names the globals from the PDB and shows how bl and r12b are set in DllInitialize.
param(
    [string]$Binary = 'storport.sys',
    [string]$Pdb = 'C:\Temp\claude\C--Users-Rev-Oconner-terminal-temp\0e176570-1dcc-481e-aee1-e01d7557119e\scratchpad\symbols\CFD59EEA80EE43ACE6BF72940618B9901_storport.pdb',
    [long[]]$Globals = @(0x172862, 0x172874),
    [long]$DllInitialize = 0xA6200
)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public class PeCode
{
    public byte[] B;
    public List<uint[]> Sections = new List<uint[]>();
    public List<string> Names = new List<string>();
    public Dictionary<uint, string> Imports = new Dictionary<uint, string>();
    public PeCode(string path)
    {
        B = File.ReadAllBytes(path);
        int e = BitConverter.ToInt32(B, 0x3C);
        int opt = e + 24;
        bool plus = BitConverter.ToUInt16(B, opt) == 0x20b;
        ushort nsec = BitConverter.ToUInt16(B, e + 6);
        ushort optsz = BitConverter.ToUInt16(B, e + 20);
        int sh = opt + optsz;
        for (int i = 0; i < nsec; i++)
        {
            int o = sh + i * 40;
            Names.Add(Encoding.ASCII.GetString(B, o, 8).TrimEnd('\0'));
            Sections.Add(new uint[] { BitConverter.ToUInt32(B, o + 12), BitConverter.ToUInt32(B, o + 8), BitConverter.ToUInt32(B, o + 20), BitConverter.ToUInt32(B, o + 16), BitConverter.ToUInt32(B, o + 36) });
        }
        int dd = opt + (plus ? 112 : 96);
        long imp = RvaToOff(BitConverter.ToUInt32(B, dd + 8));
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
    public bool IsCode(long rva) { foreach (var s in Sections) { if (rva >= s[0] && rva < s[0] + Math.Max(s[1], s[3])) return (s[4] & 0x20000000) != 0; } return false; }

    // rip relative references: any 4 byte displacement d at code position p such that rva(p)+4+k+d == target for k in 0..1 (k covers a trailing imm8)
    public List<string> RefsTo(long target)
    {
        var res = new List<string>();
        for (int si = 0; si < Sections.Count; si++)
        {
            var s = Sections[si];
            if ((s[4] & 0x20000000) == 0) continue;
            long a = s[2], z = s[2] + s[3];
            for (long p = a; p + 4 <= z; p++)
            {
                int d = BitConverter.ToInt32(B, (int)p);
                long rva = OffToRva(p);
                for (int k = 0; k <= 1; k++)
                {
                    if (rva + 4 + k + d == target)
                    {
                        var sb = new StringBuilder();
                        for (long q = p - 4; q < p + 4 + k + 1; q++) sb.Append(B[q].ToString("X2")).Append(' ');
                        res.Add(rva + "|" + k + "|" + sb.ToString().Trim());
                    }
                }
            }
        }
        return res;
    }
    public List<string> CallsIn(uint startRva, uint endRva)
    {
        var res = new List<string>();
        long a = RvaToOff(startRva), z = RvaToOff(endRva);
        for (long i = a; i < z - 5; i++)
        {
            if (B[i] == 0xE8) { int rel = BitConverter.ToInt32(B, (int)i + 1); long s = OffToRva(i); long t = s + 5 + rel; if (IsCode(t)) res.Add(s + "|E8|" + t); }
            else if (B[i] == 0xFF && B[i + 1] == 0x15) { int rel = BitConverter.ToInt32(B, (int)i + 2); long s = OffToRva(i); long t = s + 6 + rel; if (Imports.ContainsKey((uint)t)) res.Add(s + "|IAT|" + t); }
        }
        return res;
    }
}

public static class PdbPub2
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

$pe = New-Object PeCode((Join-Path $env:SystemRoot "System32\drivers\$Binary"))
$syms = New-Object System.Collections.ArrayList
foreach ($s in [PdbPub2]::All($Pdb)) { $p = $s.Split('|', 3); $rva = $pe.SegOffToRva([int]$p[0], [uint32]$p[1]); if ($rva -ge 0) { [void]$syms.Add([pscustomobject]@{ Rva = [long]$rva; Name = $p[2] }) } }
$sorted = @($syms | Sort-Object Rva -Unique)
$rvas = [long[]]($sorted | ForEach-Object { $_.Rva })
function SymAt([long]$rva) {
    $idx = [Array]::BinarySearch($rvas, $rva); if ($idx -lt 0) { $idx = (-bnot $idx) - 1 }
    if ($idx -lt 0) { return $null }
    [pscustomobject]@{ Name = $sorted[$idx].Name; Start = $sorted[$idx].Rva; End = $(if ($idx + 1 -lt $sorted.Count) { $sorted[$idx + 1].Rva } else { $sorted[$idx].Rva + 0x1000 }) }
}
"sections: " + (($pe.Names | ForEach-Object -Begin { $i = 0 } -Process { $s = $pe.Sections[$i]; $i++; '{0}(rva 0x{1:X} {2})' -f $_, $s[0], ($(if ($s[4] -band 0x20000000) { 'code' } else { 'data' })) }) -join ' ')

"== what the PDB calls the two globals"
foreach ($g in $Globals) { $x = SymAt $g; "   0x{0:X}  {1}  (symbol {2} +0x{3:X})" -f $g, ($(if ($x.Start -eq $g) { 'exact' } else { 'nearest' })), $x.Name, ($g - $x.Start) }

"== how bl and r12b are set in DllInitialize before the feature checks (look for xor ebx,ebx = 33 DB, mov r12d,1 = 41 BC 01 00 00 00, mov r12d,edi and similar)"
$o = $pe.RvaToOff([uint32]$DllInitialize)
$pro = $pe.B[$o..($o + 0x60)]
"   +0x00: " + (($pro | ForEach-Object { $_.ToString('X2') }) -join ' ')

$readers = @{}
foreach ($g in $Globals) {
    ""
    "== references to global 0x{0:X}" -f $g
    foreach ($r in $pe.RefsTo($g)) {
        $p = $r.Split('|'); $rva = [long]$p[0]; $f = SymAt $rva
        "   rva 0x{0:X}  in {1} +0x{2:X}   bytes {3}" -f $rva, $f.Name, ($rva - $f.Start), $p[2]
        if ($f.Name -ne 'DllInitialize') { $readers[$f.Name] = $f }
    }
}

foreach ($name in ($readers.Keys | Sort-Object)) {
    $f = $readers[$name]
    ""
    "#### {0}  rva 0x{1:X} to 0x{2:X}, calls in order:" -f $name, $f.Start, $f.End
    $n = 0
    foreach ($c in $pe.CallsIn([uint32]$f.Start, [uint32]$f.End)) {
        $p = $c.Split('|'); $site = [long]$p[0]; $t = [long]$p[2]
        $label = if ($p[1] -eq 'IAT') { $pe.Imports[[uint32]$t] } else { $x = SymAt $t; if ($x -and $x.Start -eq $t) { $x.Name } else { 'sub_{0:X}' -f $t } }
        "   +0x{0:X4}  {1}" -f ($site - $f.Start), $label
        if (++$n -ge 70) { '   ... truncated'; break }
    }
}
