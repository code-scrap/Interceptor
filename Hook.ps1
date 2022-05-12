Get-Process | where {$_.Id  -eq $pid} | select -ExpandProperty modules | group -Property FileName | select name
Get-Process -Id $pid | select -ExpandProperty modules | group -Property FileName | select name

$modules = Get-Process powershell_ise | select -ExpandProperty modules

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
 
public static class User32
{
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
        public static extern bool MessageBox(
            IntPtr hWnd,     /// Parent window handle 
            String text,     /// Text message to display
            String caption,  /// Window caption
            int options);    /// MessageBox type
}
"@
 
[User32]::MessageBox(0,"Text","Caption",0) |Out-Null


function Captain-Hook {
    Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
     
    public static class Kernel32
    {
        [DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
            public static extern IntPtr LoadLibraryA(
                [MarshalAs(UnmanagedType.LPStr)]string lpFileName);
             
        [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
            public static extern IntPtr GetProcAddress(
                IntPtr hModule,
                string procName);
        [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
	        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
	
    }
     
    
    // Add Virtual Protect
    // Add WriteMemory
    // Add Excpetion Handling


"@
 
   
$LibHandle = [Kernel32]::LoadLibraryA("C:\Windows\System32\sspicli.dll")
$FuncHandleEnc = [Kernel32]::GetProcAddress($LibHandle, "EncryptMessage")
$FuncHandleDec = [Kernel32]::GetProcAddress($LibHandle, "DecryptMessage")
$OldProtect = [Int]0
[Kernel32]::VirtualProtect([IntPtr]$FuncHandleEnc, 1, 0x04 , [ref]$OldProtect);
[Kernel32]::VirtualProtect([IntPtr]$FuncHandleDec, 1, 0x04 , [ref]$OldProtect);
  

$LibHandle
$FuncHandleEnc
$FuncHandleDec

[console]::ReadLine()
    
    
    
    
}
Captain-Hook

