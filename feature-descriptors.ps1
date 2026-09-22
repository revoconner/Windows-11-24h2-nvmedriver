# Read only. Enumerates the WIL feature descriptor table compiled into a kernel binary (56 byte records: feature ID, flags, three pointers into the image) and cross references every ID with the feature store and ViVeTool's name dictionary. Finds gates that have no public ID yet.
param(
    [string[]]$Binaries = @('storport.sys', 'stornvme.sys', 'nvmedisk.sys', 'disk.sys', 'classpnp.sys'),
    [uint32[]]$Extra = @(48613417, 61152952, 55369237, 60786016, 59254307),
    [uint32[]]$ExtraObfuscated = @(1409234060),
    [string]$ViVeTool = 'C:\PortableProgs\standalone_tools\ViVeTool.exe'
)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public class PeImage
{
    public byte[] B;
    public ulong ImageBase;
    public uint SizeOfImage;
    public List<uint[]> Sections = new List<uint[]>();
    public PeImage(string path)
    {
        B = File.ReadAllBytes(path);
        int e = BitConverter.ToInt32(B, 0x3C);
        int opt = e + 24;
        ushort magic = BitConverter.ToUInt16(B, opt);
        ImageBase = magic == 0x20b ? BitConverter.ToUInt64(B, opt + 24) : BitConverter.ToUInt32(B, opt + 28);
        SizeOfImage = BitConverter.ToUInt32(B, opt + 56);
        ushort nsec = BitConverter.ToUInt16(B, e + 6);
        ushort optsz = BitConverter.ToUInt16(B, e + 20);
        int sh = opt + optsz;
        for (int i = 0; i < nsec; i++)
        {
            int o = sh + i * 40;
            Sections.Add(new uint[] { BitConverter.ToUInt32(B, o + 12), BitConverter.ToUInt32(B, o + 8), BitConverter.ToUInt32(B, o + 20), BitConverter.ToUInt32(B, o + 16) });
        }
    }
    public bool InImage(ulong va) { return va >= ImageBase && va < ImageBase + SizeOfImage; }
    public long VaToOff(ulong va)
    {
        if (!InImage(va)) return -1;
        ulong rva = va - ImageBase;
        foreach (var s in Sections) { if (rva >= s[0] && rva < s[0] + Math.Max(s[1], s[3])) return (long)(rva - s[0] + s[2]); }
        return -1;
    }
    public string StrAt(ulong va)
    {
        long off = VaToOff(va);
        if (off < 0 || off >= B.Length) return "";
        var sb = new StringBuilder();
        for (long i = off; i < B.Length && sb.Length < 90; i++) { byte c = B[i]; if (c >= 0x20 && c < 0x7F) sb.Append((char)c); else break; }
        if (sb.Length >= 3) return sb.ToString();
        sb.Length = 0;
        for (long i = off; i + 1 < B.Length && sb.Length < 90; i += 2) { byte c = B[i]; if (c >= 0x20 && c < 0x7F && B[i + 1] == 0) sb.Append((char)c); else break; }
        if (sb.Length >= 3) return sb.ToString();
        return "";
    }
    public bool LooksLikeDescriptor(long i)
    {
        if (i < 0 || i + 0x38 > B.Length) return false;
        uint id = BitConverter.ToUInt32(B, (int)i);
        if (id < 5000000 || id > 200000000) return false;
        int ok = 0;
        for (int k = 0x20; k <= 0x30; k += 8) { if (InImage(BitConverter.ToUInt64(B, (int)i + k))) ok++; }
        return ok >= 2;
    }
    public List<long> FindDescriptors()
    {
        var res = new List<long>();
        for (long i = 0; i + 0x70 <= B.Length; i += 4)
        {
            if (LooksLikeDescriptor(i) && (LooksLikeDescriptor(i + 0x38) || LooksLikeDescriptor(i - 0x38))) res.Add(i);
        }
        return res;
    }
}

public static class FeatId
{
    static uint Swap(uint x) { x = (x >> 16) | (x << 16); return ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8); }
    static uint Rol1(uint v) { return (v << 1) | (v >> 31); }
    static uint Ror1(uint v) { return (v >> 1) | (v << 31); }
    public static uint Obfuscate(uint id) { return Rol1(Swap(id ^ 0x74161A4E) ^ 0x8FB23D4F) ^ 0x833EA8FF; }
    public static uint Deobfuscate(uint id) { return Swap(Ror1(id ^ 0x833EA8FF) ^ 0x8FB23D4F) ^ 0x74161A4E; }
}
'@

$priorityNames = @{ 0 = 'ImageDefault'; 1 = 'EKB'; 2 = 'Safeguard'; 3 = 'ImageDefaultEditionOverride'; 4 = 'Service'; 6 = 'Dynamic'; 8 = 'User'; 9 = 'Security'; 10 = 'UserPolicy'; 12 = 'Test'; 15 = 'ImageOverride' }
$stateNames = @{ 0 = 'Default'; 1 = 'Disabled'; 2 = 'Enabled' }

$store = @{}
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides' | ForEach-Object {
    $pri = [int]$_.PSChildName
    Get-ChildItem $_.PSPath | ForEach-Object {
        $obf = [uint32]0
        if ([uint32]::TryParse($_.PSChildName, [ref]$obf)) {
            $id = [FeatId]::Deobfuscate($obf)
            if (-not $store.ContainsKey($id)) { $store[$id] = @() }
            $pn = $priorityNames[$pri]; if (-not $pn) { $pn = "P$pri" }
            $sn = $stateNames[[int]$_.GetValue('EnabledState')]; if (-not $sn) { $sn = "S$($_.GetValue('EnabledState'))" }
            $store[$id] += "$pn=$sn"
        }
    }
}

$nameCache = @{}
function FeatureName([uint32]$id) {
    if ($nameCache.ContainsKey($id)) { return $nameCache[$id] }
    $n = ''
    if (Test-Path $ViVeTool) {
        $first = & $ViVeTool /query /id:$id 2>&1 | Where-Object { $_ -match '^\[' } | Select-Object -First 1
        if ($first -match '\((.+)\)\s*$') { $n = $Matches[1] }
    }
    $nameCache[$id] = $n
    return $n
}

"== extra IDs, both forms"
foreach ($x in $Extra) { "{0,-10} registry name {1,-11} {2,-32} {3}" -f $x, [FeatId]::Obfuscate($x), (FeatureName $x), ($(if ($store.ContainsKey($x)) { $store[$x] -join ', ' } else { 'no store entry' })) }
foreach ($o in $ExtraObfuscated) { $d = [FeatId]::Deobfuscate($o); "registry name {0,-11} is feature {1,-10} {2,-32} {3}" -f $o, $d, (FeatureName $d), ($(if ($store.ContainsKey($d)) { $store[$d] -join ', ' } else { 'no store entry' })) }

$drv = Join-Path $env:SystemRoot 'System32\drivers'
foreach ($name in $Binaries) {
    $p = Join-Path $drv $name
    if (-not (Test-Path $p)) { ""; "== {0}: not present" -f $name; continue }
    $pe = New-Object PeImage($p)
    $descs = $pe.FindDescriptors()
    ""
    "== {0}  {1}  image base 0x{2:X}  descriptors found: {3}" -f $name, (Get-Item $p).VersionInfo.FileVersion, $pe.ImageBase, $descs.Count
    foreach ($off in $descs) {
        $id = [BitConverter]::ToUInt32($pe.B, $off)
        $flags = [BitConverter]::ToUInt32($pe.B, $off + 4)
        $q8 = [BitConverter]::ToUInt64($pe.B, $off + 8)
        $strs = @()
        foreach ($k in 0x20, 0x28, 0x30) { $va = [BitConverter]::ToUInt64($pe.B, $off + $k); $s = $pe.StrAt($va); if ($s) { $strs += $s } }
        $cfg = if ($store.ContainsKey($id)) { $store[$id] -join ', ' } else { 'no store entry' }
        $inExtra = if ($Extra -contains $id) { ' <== of interest' } else { '' }
        "  0x{0:X6} id={1,-10} flags=0x{2:X8} p8={3} name={4,-30} store: {5}{6}" -f $off, $id, $flags, ($(if ($q8) { 'ptr' } else { '0' })), (FeatureName $id), $cfg, $inExtra
        if ($strs.Count) { "           strings: " + ($strs -join '  |  ') }
    }
}
