DotNetHooking
==============

Introduction
-------------
This project demonstrates how to use the .NET native code hooking technique. For
more details of the technique, see the attached presentation slides.

Source Navigation
--------------
The high level flow of this code is:
 1. This assembly is loaded via a mechanism of AppDomainManager
 2. The HookScanContent class is instantiated registering an assembly load
    event handler
 3. When System.Management.Automation, which contains implementation of our
    target method "ScanContent", locates its native code address and installs
    a hook on it to redirect to the ScanContentHookHandler method
 4. When PowerShell is executed and the ScanContent is called, our
    ScanContentHookHandler is executed instead of original ScanContent

Hints
------
Few things worth noting:
 1. This project targets .NET 2.0. This lets this assembly be loadable on
    practically any platforms since .NET Framework 2.0 is installed by
    default since Windows 7. Also, such an assembly can be loaded into a
    process using a newer version of .NET Framework. Therefore, such an
    assembly can be loaded into through PowerShell v2 to v5 universally.
 2. This assembly is signed and compiled as a strongly named assembly. This
    allows this assembly to be registered with Global Assembly Cache (GAC).
    Registering with GAC is required to load this assembly into any process
    because CLR cannot find this assembly when this assembly is registered
    as an AppDomainManager but not located in the folder where an EXE file
    of the process exists or GAC either. Registering this assembly with GAC
    allows CLR to find it regardless of where the EXE file exists.
 3. Code in this project intentionally emits error checks or exception
    handling. One using this code should add error handling as necessary.

Installation
----------
As noted above, this assembly must be registered with GAC, or it located in
the same folder as a target executable file (powershell.exe, in our case).
While registering with GAC will be required in the real use cases, skipping
registration is more convenient for debugging and testing. The below is the
instructions for both ways:

No GAC Installation (+ testing with locally copied powershell.exe)

 1. Build the solution with Visual Studio 2017
 2. Launch the command prompt and navigate to an output folder
 
        > cd <Folder where the DLL was built>
 
 3. Copy powershell.exe to the current folder for testing
 
        > copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe . /y
 
 4. Set environment variable to specify a custome AppDomainManager
 
        > set APPDOMAIN_MANAGER_ASM=HookingAssembly, Version=1.0.0.0, Culture=neutral, PublicKeyToken=c8b8e7ea5047757d, processorArchitecture=MSIL
        > set APPDOMAIN_MANAGER_TYPE=HookingAssembly.CustomeAppDomainManager1
 
 5. Start the copied powershell.exe
 
        > powershell.exe
        [*] AssemblyLoad event handler registered.
        [*] Loading assembly System
        [*] Loading assembly Microsoft.PowerShell.ConsoleHost
        [*] Loading assembly System.Management.Automation
        [*] The ScanContent method has been hooked.
        Windows PowerShell
        Copyright (C) Microsoft Corporation.All rights reserved.

GAC Installation (+ powershell.exe)
 1. Build the solution with Visual Studio 2017
 2. Launch the elevated command prompt for Visual Studio 2017 and navigate to an
    output folder

        > cd <Folder where the DLL was built>

 3. Install the assembly to GAC

        > gacutil /i HookingAssembly.dll
        Microsoft (R) .NET Global Assembly Cache Utility.Version 4.0.30319.0
        Copyright (c) Microsoft Corporation.All rights reserved.

        Assembly successfully added to the cache

 4. Set environment variable to specify a custome AppDomainManager

        > set APPDOMAIN_MANAGER_ASM=HookingAssembly, Version=1.0.0.0, Culture=neutral, PublicKeyToken=c8b8e7ea5047757d, processorArchitecture=MSIL
        > set APPDOMAIN_MANAGER_TYPE=HookingAssembly.CustomeAppDomainManager1

 5. Add the current folder to %PATH%, so that the hooking DLLs can be found

        > set PATH=%PATH%;%~dp0

 6. Start powershell.exe

        > powershell

To uninstall the assembly from GAC:

    > gacutil /u HookingAssembly


Simulate Detection by AMSI
---------------------------

On the hooked PowerShell session, run this command:

    PS> 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

     At line:1 char:1
     + 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* ...
     + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     This script contains malicious content and has been blocked by your antivirus software.
         + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
         + FullyQualifiedErrorId : ScriptContainedMaliciousContent
