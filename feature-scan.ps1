# Read only. Maps the Windows feature store (Control\FeatureManagement\Overrides) to real feature IDs, then looks for those IDs inside the storage driver binaries, to show which feature flags this build's NVMe stack references and what state each one is in. Rerun after a cumulative update to see whether Microsoft moved the flags again.
param(
    [uint32[]]$Interest = @(60786016, 48433719),
    [uint32[]]$InterestObfuscated = @(735209102, 1853569164, 156965516, 1176759950),
    [string]$ViVeTool = 'C:\PortableProgs\standalone_tools\ViVeTool.exe',
    [string[]]$StorageBinaries = @('stornvme.sys', 'storport.sys', 'nvmedisk.sys', 'disk.sys', 'classpnp.sys', 'partmgr.sys', 'EhStorClass.sys', 'storahci.sys')
)

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

public static class FeatScan
{
    static uint Swap(uint x) { x = (x >> 16) | (x << 16); return ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8); }
    static uint Rol1(uint v) { return (v << 1) | (v >> 31); }
    static uint Ror1(uint v) { return (v >> 1) | (v << 31); }
    // Same transform ViVe uses between a feature ID and its registry key name
    public static uint Obfuscate(uint id) { return Rol1(Swap(id ^ 0x74161A4E) ^ 0x8FB23D4F) ^ 0x833EA8FF; }
    public static uint Deobfuscate(uint id) { return Swap(Ror1(id ^ 0x833EA8FF) ^ 0x8FB23D4F) ^ 0x74161A4E; }

    public static Dictionary<uint, List<int>> Scan(string file, HashSet<uint> ids)
    {
        var res = new Dictionary<uint, List<int>>();
        byte[] b = File.ReadAllBytes(file);
        for (int i = 0; i + 4 <= b.Length; i++)
        {
            uint v = BitConverter.ToUInt32(b, i);
            if (!ids.Contains(v)) continue;
            List<int> l;
            if (!res.TryGetValue(v, out l)) { l = new List<int>(); res[v] = l; }
            l.Add(i);
        }
        return res;
    }

    public static List<string> Strings(string file, int min, string[] needles)
    {
        var found = new List<string>();
        var seen = new HashSet<string>();
        byte[] b = File.ReadAllBytes(file);
        var sb = new StringBuilder();
        Action flush = () =>
        {
            if (sb.Length >= min)
            {
                string s = sb.ToString();
                foreach (string n in needles)
                {
                    if (s.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) { if (seen.Add(s)) found.Add(s); break; }
                }
            }
            sb.Length = 0;
        };
        for (int i = 0; i < b.Length; i++) { if (b[i] >= 0x20 && b[i] < 0x7F) sb.Append((char)b[i]); else flush(); }
        flush();
        int j = 0;
        while (j + 1 < b.Length)
        {
            if (b[j] >= 0x20 && b[j] < 0x7F && b[j + 1] == 0) { sb.Append((char)b[j]); j += 2; }
            else { flush(); j += 1; }
        }
        flush();
        return found;
    }
}
'@

$priorityNames = @{ 0 = 'ImageDefault'; 1 = 'EKB'; 2 = 'Safeguard'; 4 = 'Service'; 6 = 'Dynamic'; 8 = 'User'; 9 = 'Security'; 10 = 'UserPolicy'; 12 = 'Test'; 15 = 'ImageOverride' }
$stateNames = @{ 0 = 'Default'; 1 = 'Disabled'; 2 = 'Enabled' }

function Describe($entries) {
    ($entries | Sort-Object Priority | ForEach-Object {
        $pn = $priorityNames[[int]$_.Priority]; if (-not $pn) { $pn = 'Reserved' }
        $sn = $stateNames[[int]$_.State]; if (-not $sn) { $sn = "State$($_.State)" }
        "$pn($($_.Priority))=$sn"
    }) -join ', '
}

function FeatureName([uint32]$id) {
    if (-not (Test-Path $ViVeTool)) { return '' }
    $first = & $ViVeTool /query /id:$id 2>&1 | Where-Object { $_ -match '^\[' } | Select-Object -First 1
    if ($first -match '\((.+)\)\s*$') { return $Matches[1] }
    return ''
}

"== self test of the ID transform, against the two keys ViVeTool wrote on 2026-09-18"
"48433719 obfuscates to $([FeatScan]::Obfuscate(48433719)), expected 1853569164"
"60786016 obfuscates to $([FeatScan]::Obfuscate(60786016)), expected 3244671118"
if ([FeatScan]::Obfuscate(48433719) -ne 1853569164 -or [FeatScan]::Obfuscate(60786016) -ne 3244671118) { 'TRANSFORM IS WRONG, stopping.'; return }

$root = 'HKLM:\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides'
$store = @{}
Get-ChildItem $root | ForEach-Object {
    $pri = [int]$_.PSChildName
    Get-ChildItem $_.PSPath | ForEach-Object {
        $obf = [uint32]0
        if ([uint32]::TryParse($_.PSChildName, [ref]$obf)) {
            $id = [FeatScan]::Deobfuscate($obf)
            if (-not $store.ContainsKey($id)) { $store[$id] = New-Object System.Collections.ArrayList }
            [void]$store[$id].Add([pscustomobject]@{ Priority = $pri; State = $_.GetValue('EnabledState'); Obf = $obf })
        }
    }
}
""
"== feature store: $($store.Count) distinct features configured"

$all = New-Object System.Collections.ArrayList
foreach ($i in $Interest) { [void]$all.Add([uint32]$i) }
foreach ($o in $InterestObfuscated) { [void]$all.Add([FeatScan]::Deobfuscate($o)) }
$all = $all | Sort-Object -Unique
""
"== features of interest"
foreach ($id in $all) {
    $cfg = if ($store.ContainsKey($id)) { Describe $store[$id] } else { 'no entry at any priority' }
    "{0,-10} registry name {1,-11} {2,-28} {3}" -f $id, [FeatScan]::Obfuscate($id), (FeatureName $id), $cfg
}

$drv = Join-Path $env:SystemRoot 'System32\drivers'
$set = New-Object 'System.Collections.Generic.HashSet[uint32]'
foreach ($id in $all) { [void]$set.Add([uint32]$id); [void]$set.Add([FeatScan]::Obfuscate($id)) }
""
"== pass A: which kernel binaries contain the IDs of interest, as a 32 bit constant, in either form"
$files = @(Get-ChildItem $drv -Filter *.sys -File) + @(Get-Item (Join-Path $env:SystemRoot 'System32\ntoskrnl.exe'))
$anyA = $false
foreach ($f in $files) {
    try { $hits = [FeatScan]::Scan($f.FullName, $set) } catch { continue }
    foreach ($k in $hits.Keys) {
        $anyA = $true
        $form = if ($all -contains $k) { 'feature ID' } else { "registry name of $([FeatScan]::Deobfuscate($k))" }
        "{0,-22} {1,-11} ({2}) at offsets {3}" -f $f.Name, $k, $form, (($hits[$k] | Select-Object -First 6 | ForEach-Object { '0x{0:X}' -f $_ }) -join ', ')
    }
}
if (-not $anyA) { 'none of the IDs of interest appear in any driver or in ntoskrnl.exe' }

$big = New-Object 'System.Collections.Generic.HashSet[uint32]'
foreach ($id in $store.Keys) { [void]$big.Add([uint32]$id) }
foreach ($id in $all) { [void]$big.Add([uint32]$id) }
""
"== pass B: every configured feature ID found inside the storage binaries. 4 byte aligned hits are the believable ones, unaligned hits are often coincidence."
foreach ($name in $StorageBinaries) {
    $p = Join-Path $drv $name
    if (-not (Test-Path $p)) { "{0}: not present" -f $name; continue }
    $fi = Get-Item $p
    "-- {0}  {1}  {2:N0} bytes" -f $name, $fi.VersionInfo.FileVersion, $fi.Length
    $hits = [FeatScan]::Scan($p, $big)
    if ($hits.Count -eq 0) { '   no configured feature ID found'; continue }
    foreach ($k in ($hits.Keys | Sort-Object)) {
        $aligned = @($hits[$k] | Where-Object { $_ % 4 -eq 0 }).Count
        $cfg = if ($store.ContainsKey($k)) { Describe $store[$k] } else { 'no store entry' }
        "   {0,-10} hits={1} aligned={2} {3,-34} {4}" -f $k, $hits[$k].Count, $aligned, (FeatureName $k), $cfg
    }
}

""
"== strings in the storage binaries that mention the native path"
$needles = @('NvmeDisk', 'GenNvme', 'NativeNvme', 'StorMQ', 'Feature_', 'Velocity')
foreach ($name in $StorageBinaries) {
    $p = Join-Path $drv $name
    if (-not (Test-Path $p)) { continue }
    $s = [FeatScan]::Strings($p, 6, $needles)
    "-- {0}: {1} matching strings" -f $name, $s.Count
    $s | Select-Object -First 25 | ForEach-Object { "   $_" }
}
