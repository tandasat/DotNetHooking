using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using static HookingAssembly.MinHook.NativeMethods;

namespace HookingAssembly
{
    //
    // An AppDomainManager derived class used to be loaded automatically.
    //
    public class CustomeAppDomainManager1 : AppDomainManager
    {
        private readonly HookScanContent m_HookScanContent = new HookScanContent();
    }

    //
    // An implementation of .NET native code hocking against the ScanContent
    // method.
    //
    internal class HookScanContent
    {
        private static readonly AssemblyLoadEventHandler s_EventHandler =
            new AssemblyLoadEventHandler(OnAssemblyLoad);

        //
        // Constructor. Starts monitoring of assembly loading to detect a
        // target assembly (ie, System.Management.Automation).
        //
        internal
        HookScanContent (
            )
        {
            if (!AppDomain.CurrentDomain.IsDefaultAppDomain())
            {
                return;
            }

            AppDomain.CurrentDomain.AssemblyLoad += s_EventHandler;
            Console.WriteLine("[*] AssemblyLoad event handler registered.");
        }

        //
        // An assembly load event handler.
        //
        private
        static
        void
        OnAssemblyLoad (
            object Sender,
            AssemblyLoadEventArgs Args
            )
        {
            //
            // STEP1: Wait for System.Management.Automation (SMA)
            //
            string assemblyName = Args.LoadedAssembly.GetName().Name;
            Console.WriteLine("[*] Loading assembly " + assemblyName);
            if (assemblyName != "System.Management.Automation")
            {
                return;
            }

            AppDomain.CurrentDomain.AssemblyLoad -= s_EventHandler;
            Assembly smaAssembly = Args.LoadedAssembly;

            //
            // You may want to break into a debugger for debugging.
            //
            //Debugger.Launch();

            //
            // STEP2: Determine a version of SMA
            //
            // Need a version of SMA since the ScanContent method exists only
            // in PowerShell v5 or later. PowerShell version can be obtained
            // via the PSVersion property of the PSVersionInfo class.
            //
            Type psVersionInfo = smaAssembly.GetType(
                                "System.Management.Automation.PSVersionInfo");
            PropertyInfo psVersion = psVersionInfo.GetProperty(
                                "PSVersion",
                                BindingFlags.Static | BindingFlags.NonPublic,
                                null,
                                typeof(Version),
                                Type.EmptyTypes,
                                null);
            var version = (Version)psVersion.GetValue(null, null);
            if (version.Major != 5)
            {
                Console.WriteLine("[-] Unsupported PowerShell version detected.");
                return;
            }

            //
            // STEP3: Find methods via reflection
            //
            // We need tree methods per target method:
            //  target - A method to be hooked. It normally exists out side of
            //           out code.
            //  handler - A detour method to be called instead of the target
            //            method after a hook is installed.
            //  trampoline - A method used to call an original of the target
            //               method after a hook is installed.
            //
            const BindingFlags anyType = BindingFlags.Static |
                                         BindingFlags.Instance |
                                         BindingFlags.Public |
                                         BindingFlags.NonPublic;

            //
            // Indicates what parameters the methods take. Reflection requires
            // this information on the top of a method name since a method can
            // be overloaded for a different set of parameters.
            //
            // In our case, the methods are defined as follows:
            //  static AMSI_RESULT ScanContent(string Content,
            //                                 string SourceMetadata);
            //  static AMSI_RESULT ScanContentHookHandler(string Content,
            //                                            string SourceMetadata);
            //  static AMSI_RESULT ScanContentTrampoline(string Content,
            //                                           string SourceMetadata);
            //
            var targetMethodType = new Type[] { typeof(string), typeof(string), };
            var handlerMethodType = new Type[] { typeof(string), typeof(string), };
            var trampolineMethodType = new Type[] { typeof(string), typeof(string), };

            Type targetMethodClass = smaAssembly.GetType(
                                    "System.Management.Automation.AmsiUtils");
            Type handlerMethodClass = typeof(HookScanContent);
            Type trampolineMethodClass = typeof(HookScanContent);

            MethodInfo target = targetMethodClass.GetMethod(
                                                    "ScanContent",
                                                    anyType,
                                                    null,
                                                    targetMethodType,
                                                    null);
            MethodInfo hookHandler = handlerMethodClass.GetMethod(
                                                    "ScanContentHookHandler",
                                                    anyType,
                                                    null,
                                                    handlerMethodType,
                                                    null);
            MethodInfo trampoline = trampolineMethodClass.GetMethod(
                                                    "ScanContentTrampoline",
                                                    anyType,
                                                    null,
                                                    trampolineMethodType,
                                                    null);

            //
            // STEP4: Get addresses of native code of the methods
            //
            RuntimeHelpers.PrepareMethod(target.MethodHandle);
            RuntimeHelpers.PrepareMethod(hookHandler.MethodHandle);
            RuntimeHelpers.PrepareMethod(trampoline.MethodHandle);

            IntPtr targetAddr = target.MethodHandle.GetFunctionPointer();
            IntPtr hookHandlerAddr = hookHandler.MethodHandle.GetFunctionPointer();
            IntPtr trampolineAddr = trampoline.MethodHandle.GetFunctionPointer();

            //
            // STEP5: Install a hook on to the target method
            //
            // Overwrite native code of the ScanContent method. This is standard
            // inline hooking, only differences are that we initiate hooking
            // from C# (typically C/C++) and a target is compiled .NET native
            // code.
            //
            // This example code uses MinHook (https://github.com/TsudaKageyu/minhook)
            // for installing hooks since the author did not find any suitable
            // inline hooking library for C#.
            //
            if (!MinHook.InstallHook(targetAddr, hookHandlerAddr, trampolineAddr))
            {
                return;
            }

            //
            // STEP6: PROFIT!
            //
            Console.WriteLine("[*] The ScanContent method has been hooked.");
        }

        private enum AMSI_RESULT
        {
            AMSI_RESULT_CLEAN = 0,
            AMSI_RESULT_NOT_DETECTED = 1,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
            AMSI_RESULT_DETECTED = 32768,
        }

        //
        // A methods that is executed when the target method (ie, ScanContent)
        // is called after a hook is installed.
        //
        private
        static
        AMSI_RESULT
        ScanContentHookHandler (
            string Content,
            string SourceMetadata
            )
        {
            Console.WriteLine("[EMULATOR] " + Content);

            //
            // Perform our own scan here. If maliciousness is detected, return
            // AMSI_RESULT_DETECTED.
            //
            const string eicar =
                @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            if (Content.IndexOf(eicar) != -1)
            {
                return AMSI_RESULT.AMSI_RESULT_DETECTED;
            }

            //
            // Call the original implementation of the ScanContent otherwise.
            //
            return ScanContentTrampoline(Content, SourceMetadata);
        }

        //
        // A dummy method that is overwritten to jump to the original
        // implementation of the ScanContent method.
        //
        [MethodImpl(MethodImplOptions.NoInlining)]
        private
        static
        AMSI_RESULT
        ScanContentTrampoline (
            string Content,
            string SourceMetadata
            )
        {
            //
            // This should never happen.
            //
            // NB: Be careful with updating the 'trampoline' method. It must
            // be large enough to be safely overwritten with the STEP5 above.
            // Making the 'trampoline' method smaller than necessary bytes to
            // install JMP could corrupt other, irrelevant method on memory.
            // For example, this Trace.Assert cannot be Debug.Assert to keep a
            // size of this method on release build.
            //
            Trace.Assert(false);
            throw new Exception("It is a bug. Fix it bro!");
        }

    }

#region MinHook specific. You very likely need your code for hooking.
    internal static class MinHook
    {
        //
        // Helper function to install hook using MinHook.
        //
        internal
        static
        bool
        InstallHook (
            IntPtr TargetAddr,
            IntPtr HookHandlerAddr,
            IntPtr TrampolineAddr
            )
        {
            //
            // This code expects either MinHook.x86.dll or MinHook.x64.dll is
            // located in any of the DLL search path. Such as the current folder
            // and %PATH%.
            //
            string architecture = (IntPtr.Size == 4) ? "x86" : "x64";
            string dllPath = "MinHook." + architecture + ".dll";
            IntPtr moduleHandle = LoadLibrary(dllPath);
            if (moduleHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] An inline hook DLL not found. Did you locate " +
                                  dllPath + " under the DLL search path?");
                return false;
            }

            var MH_Initialize = GetExport<MH_InitializeType>(moduleHandle, "MH_Initialize");
            var MH_CreateHook = GetExport<MH_CreateHookType>(moduleHandle, "MH_CreateHook");
            var MH_EnableHook = GetExport<MH_EnableHookType>(moduleHandle, "MH_EnableHook");


            MH_STATUS status = MH_Initialize();
            Trace.Assert(status == MH_STATUS.MH_OK);

            //
            // Modify the target method to jump to the HookHandler method. The
            // original receives an address of trampoline code to call the
            // original implementation of the target method.
            //
            status = MH_CreateHook(TargetAddr, HookHandlerAddr, out IntPtr original);
            Trace.Assert(status == MH_STATUS.MH_OK);

            //
            // Modify the Trampoline method to jump to the original
            // implementation of the target method.
            //
            status = MH_CreateHook(TrampolineAddr, original, out _);
            Trace.Assert(status == MH_STATUS.MH_OK);

            //
            // Commit and activate the above two hooks.
            //
            status = MH_EnableHook(MH_ALL_HOOKS);
            Trace.Assert(status == MH_STATUS.MH_OK);

            return true;
        }

        //
        // Helper function to resolve an export of a DLL.
        //
        private
        static
        ProcType
        GetExport<ProcType> (
            IntPtr ModuleHandle,
            string ExportName
            ) where ProcType : class
        {
            //
            // Get a function pointer, convert it to delegate, and return it as
            // a requested type.
            //
            IntPtr pointer = GetProcAddress(ModuleHandle, ExportName);
            if (pointer == IntPtr.Zero)
            {
                return null;
            }

            Delegate function = Marshal.GetDelegateForFunctionPointer(
                                                            pointer,
                                                            typeof(ProcType));
            return function as ProcType;
        }

        [SuppressUnmanagedCodeSecurity]
        internal static class NativeMethods
        {
            [DllImport("kernel32.dll",
                        EntryPoint = "LoadLibraryW",
                        SetLastError = true,
                        CharSet = CharSet.Unicode)]
            internal
            static
            extern
            IntPtr
            LoadLibrary (
                string FileName
                );

            [DllImport("kernel32.dll",
                        EntryPoint = "GetProcAddress",
                        SetLastError = true,
                        CharSet = CharSet.Ansi,
                        BestFitMapping = false)]
            internal
            static
            extern
            IntPtr
            GetProcAddress (
                IntPtr Module,
                string ProcName
                );

            //
            // MinHook specific.
            //
            internal static IntPtr MH_ALL_HOOKS = IntPtr.Zero;
            internal enum MH_STATUS
            {
                MH_OK = 0,
            }

            [UnmanagedFunctionPointer(CallingConvention.Winapi)]
            internal
            delegate
            MH_STATUS
            MH_InitializeType (
                );

            [UnmanagedFunctionPointer(CallingConvention.Winapi)]
            internal
            delegate
            MH_STATUS
            MH_CreateHookType (
                IntPtr Target,
                IntPtr Detour,
                out IntPtr Original
                );

            [UnmanagedFunctionPointer(CallingConvention.Winapi)]
            internal
            delegate
            MH_STATUS
            MH_EnableHookType (
                IntPtr Target
                );
        }
    }
#endregion
}
