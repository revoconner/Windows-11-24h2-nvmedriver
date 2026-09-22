# Read only, apart from downloading public PDBs into the given folder. For each binary: read the RSDS debug record, fetch the matching PDB from Microsoft's public symbol server, pull the public symbols whose name contains "Feature_", and map each one to a file offset so it can be matched to the descriptor table found by feature-descriptors.ps1.
param(
    [string[]]$Binaries = @('storport.sys', 'stornvme.sys', 'classpnp.sys', 'nvmedisk.sys'),
    [string]$SymDir = 'C:\Temp\claude\C--Users-Rev-Oconner-terminal-temp\0e176570-1dcc-481e-aee1-e01d7557119e\scratchpad\symbols'
)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public class PeDbg
{
    public byte[] B;
    public ulong ImageBase;
    public List<uint[]> Sections = new List<uint[]>();
    public string PdbName = "";
    public string PdbId = "";
    public PeDbg(string path)
    {
        B = File.ReadAllBytes(path);
        int e = BitConverter.ToInt32(B, 0x3C);
        int opt = e + 24;
        ushort magic = BitConverter.ToUInt16(B, opt);
        bool pe32plus = magic == 0x20b;
        ImageBase = pe32plus ? BitConverter.ToUInt64(B, opt + 24) : BitConverter.ToUInt32(B, opt + 28);
        ushort nsec = BitConverter.ToUInt16(B, e + 6);
        ushort optsz = BitConverter.ToUInt16(B, e + 20);
        int sh = opt + optsz;
        for (int i = 0; i < nsec; i++)
        {
            int o = sh + i * 40;
            Sections.Add(new uint[] { BitConverter.ToUInt32(B, o + 12), BitConverter.ToUInt32(B, o + 8), BitConverter.ToUInt32(B, o + 20), BitConverter.ToUInt32(B, o + 16) });
        }
        int dd = opt + (pe32plus ? 112 : 96);
        uint dbgRva = BitConverter.ToUInt32(B, dd + 6 * 8);
        uint dbgSize = BitConverter.ToUInt32(B, dd + 6 * 8 + 4);
        long dbgOff = RvaToOff(dbgRva);
        for (int i = 0; i + 28 <= dbgSize; i += 28)
        {
            int d = (int)dbgOff + i;
            uint type = BitConverter.ToUInt32(B, d + 12);
            if (type != 2) continue;
            int raw = (int)BitConverter.ToUInt32(B, d + 24);
            if (Encoding.ASCII.GetString(B, raw, 4) != "RSDS") continue;
            var g = new Guid(new ReadOnlySpan<byte>(B, raw + 4, 16).ToArray());
            uint age = BitConverter.ToUInt32(B, raw + 20);
            int n = raw + 24; int len = 0; while (B[n + len] != 0) len++;
            PdbName = Path.GetFileName(Encoding.ASCII.GetString(B, n, len));
            PdbId = g.ToString("N").ToUpperInvariant() + age.ToString("X");
            break;
        }
    }
    public long RvaToOff(uint rva)
    {
        foreach (var s in Sections) { if (rva >= s[0] && rva < s[0] + Math.Max(s[1], s[3])) return rva - s[0] + s[2]; }
        return -1;
    }
    public long SegOffToFileOff(int seg, uint off)
    {
        if (seg < 1 || seg > Sections.Count) return -1;
        return RvaToOff(Sections[seg - 1][0] + off);
    }
}

public static class PdbScan
{
    // Raw scan for S_PUB32 records (kind 0x110E): len:2, kind:2, flags:4, offset:4, segment:2, name. Records that straddle an MSF page boundary are lost, which is acceptable here.
    public static List<string> Publics(string pdb, string needle)
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
            if (l < 4) continue;
            string name = Encoding.ASCII.GetString(b, n, l);
            if (name.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0) continue;
            res.Add(seg + "|" + off + "|" + name);
        }
        return res;
    }
}
'@

New-Item -ItemType Directory -Force $SymDir | Out-Null
$drv = Join-Path $env:SystemRoot 'System32\drivers'
foreach ($name in $Binaries) {
    $p = Join-Path $drv $name
    if (-not (Test-Path $p)) { "== {0}: not present" -f $name; continue }
    $pe = New-Object PeDbg($p)
    ""
    "== {0}  pdb={1}  id={2}" -f $name, $pe.PdbName, $pe.PdbId
    if (-not $pe.PdbName) { '   no RSDS record'; continue }
    $local = Join-Path $SymDir ($pe.PdbId + '_' + $pe.PdbName)
    if (-not (Test-Path $local)) {
        $url = "https://msdl.microsoft.com/download/symbols/$($pe.PdbName)/$($pe.PdbId)/$($pe.PdbName)"
        try { Invoke-WebRequest -Uri $url -OutFile $local -UseBasicParsing -ErrorAction Stop | Out-Null } catch { "   download failed: $($_.Exception.Message)"; continue }
    }
    "   pdb {0:N0} bytes" -f (Get-Item $local).Length
    $syms = [PdbScan]::Publics($local, 'Feature_')
    "   public symbols mentioning Feature_: {0}" -f $syms.Count
    foreach ($s in $syms) {
        $parts = $s.Split('|', 3)
        $seg = [int]$parts[0]; $off = [uint32]$parts[1]; $sym = $parts[2]
        $fo = $pe.SegOffToFileOff($seg, $off)
        $idText = ''
        if ($fo -ge 0 -and $fo + 4 -le $pe.B.Length -and $sym -match 'descriptor') { $idText = 'id=' + [BitConverter]::ToUInt32($pe.B, $fo) }
        "   0x{0:X6} {1,-12} {2}" -f $fo, $idText, $sym
    }
}
