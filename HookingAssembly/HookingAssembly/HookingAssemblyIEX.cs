using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security;

namespace HookingAssembly
{
    //
    // An AppDomainManager derived class used to be loaded automatically.
    //
    public class CustomeAppDomainManager2 : AppDomainManager
    {
        private readonly HookProcessRecord m_HookProcessRecord = new HookProcessRecord();
    }

    //
    // An implementation of .NET native code hocking against the ProcessRecord
    // method.
    //
    internal class HookProcessRecord
    {
        private static readonly AssemblyLoadEventHandler s_EventHandler =
            new AssemblyLoadEventHandler(OnAssemblyLoad);

        //
        // Constructor. Starts monitoring of assembly loading to detect a
        // target assembly (ie, Microsoft.PowerShell.Commands.Utility).
        //
        internal
        HookProcessRecord (
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
            // STEP1: Wait for Microsoft.PowerShell.Commands.Utility (MPCU)
            //
            string assemblyName = Args.LoadedAssembly.GetName().Name;
            Console.WriteLine("[*] Loading assembly " + assemblyName);
            if (assemblyName != "Microsoft.PowerShell.Commands.Utility")
            {
                return;
            }

            AppDomain.CurrentDomain.AssemblyLoad -= s_EventHandler;
            Assembly mpcuAssembly = Args.LoadedAssembly;

            //
            // You may want to break into a debugger for debugging.
            //
            //Debugger.Launch();

            //
            // STEP2: Find methods via reflection
            //
            const BindingFlags anyType = BindingFlags.Static |
                                         BindingFlags.Instance |
                                         BindingFlags.Public |
                                         BindingFlags.NonPublic;

            var targetMethodType = Type.EmptyTypes;
            var handlerMethodType = new Type[] { typeof(HookProcessRecord), };
            var trampolineMethodType = Type.EmptyTypes;

            Type targetMethodClass = mpcuAssembly.GetType(
                        "Microsoft.PowerShell.Commands.InvokeExpressionCommand");
            Type handlerMethodClass = typeof(HookProcessRecord);
            Type trampolineMethodClass = typeof(HookProcessRecord);

            MethodInfo target = targetMethodClass.GetMethod(
                                                    "ProcessRecord",
                                                    anyType,
                                                    null,
                                                    targetMethodType,
                                                    null);
            MethodInfo hookHandler = handlerMethodClass.GetMethod(
                                                    "ProcessRecordHookHandler",
                                                    anyType,
                                                    null,
                                                    handlerMethodType,
                                                    null);
            MethodInfo trampoline = trampolineMethodClass.GetMethod(
                                                    "ProcessRecordTrampoline",
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
            if (!MinHook.InstallHook(targetAddr, hookHandlerAddr, trampolineAddr))
            {
                return;
            }

            //
            // STEP6: PROFIT!
            //
            Console.WriteLine("[*] The ProcessRecord method has been hooked.");
        }

        //
        // A methods that is executed when the target method (ie, ProcessRecord)
        // is called after a hook is installed.
        //
        private
        static
        void
        ProcessRecordHookHandler (
            HookProcessRecord ThisObject
            )
        {
            //
            // Get content of the _command field through the Command property.
            //
            const BindingFlags anyInstanceType = BindingFlags.Instance |
                                                 BindingFlags.Public |
                                                 BindingFlags.NonPublic;

            PropertyInfo property = ThisObject.GetType().GetProperty("Command", anyInstanceType);
            var Content = (string)property.GetValue(ThisObject, null);

            //
            // A file name is unavailable.
            //
            Console.WriteLine("[IEX] " + Content);

            //
            // Perform our own scan here. If maliciousness is detected, throw an
            // exception with a message to display.
            //
            const string eicar =
                @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            if (Content.IndexOf(eicar) != -1)
            {
                const string detectionMessage =
                    "This script contains malicious content and has been blocked by" +
                    " your antivirus software.";

                throw new SecurityException(detectionMessage);
            }

            //
            // Call the original implementation of the ProcessRecord otherwise.
            //
            ThisObject.ProcessRecordTrampoline();
        }

        //
        // A dummy method that is overwritten to jump to the original
        // implementation of the ProcessRecord method.
        //
        [MethodImpl(MethodImplOptions.NoInlining)]
        private
        void
        ProcessRecordTrampoline (
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
}
