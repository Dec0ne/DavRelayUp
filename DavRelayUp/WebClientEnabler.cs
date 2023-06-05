using System.Runtime.InteropServices;
using System;
// Code take from KlezVirus: https://gist.github.com/klezVirus/af004842a73779e1d03d47e041115797
/* 
 * Simple C# PoC to enable WebClient Service Programmatically
 * Based on the C++ version from @tirannido (James Forshaw)
 * Twitter: https://twitter.com/tiraniddo
 * URL: https://www.tiraniddo.dev/2015/03/starting-webclient-service.html
 * 
 * Compile with:
 *   - 32-bit: C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe .\EtwStartWebClient.cs /unsafe
 *   - 64-bit: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe .\EtwStartWebClient.cs /unsafe
 */

namespace DavRelayUp
{
    public static class WebClientEnabler
    {

        public static bool StartWebClientService()
        {
            Guid _MS_Windows_WebClntLookupServiceTrigger_Provider = new Guid(0x22B6D684, 0xFA63, 0x4578, 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7);

            WebClientEnabledWin32.EVENT_DESCRIPTOR eventDescriptor = new WebClientEnabledWin32.EVENT_DESCRIPTOR();
            ulong regHandle = 0;

            WebClientEnabledWin32.WINERROR winError = WebClientEnabledWin32.EventRegister(
                ref _MS_Windows_WebClntLookupServiceTrigger_Provider,
                IntPtr.Zero,
                IntPtr.Zero,
                ref regHandle
            );

            if (winError == ((ulong)WebClientEnabledWin32.WINERROR.ERROR_SUCCESS))
            {
                unsafe
                {
                    if (WebClientEnabledWin32.EventWrite(
                            regHandle,
                            ref eventDescriptor,
                            0,
                            null
                            ) == WebClientEnabledWin32.WINERROR.ERROR_SUCCESS)
                    {
                        WebClientEnabledWin32.EventUnregister(regHandle);
                        return true;
                    }
                }
            }
            return false;
        }
    }

    class WebClientEnabledWin32
    {

        public enum WINERROR : ulong
        {
            ERROR_SUCCESS = 0x0,
            ERROR_INVALID_PARAMETER = 0x57,
            ERROR_INVALID_HANDLE = 0x6,
            ERROR_ARITHMETIC_OVERFLOW = 0x216,
            ERROR_MORE_DATA = 0xEA,
            ERROR_NOT_ENOUGH_MEMORY = 0x8,
            STATUS_LOG_FILE_FULL = 0xC0000188,


        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public class EVENT_DESCRIPTOR
        {
            [FieldOffset(0)] ushort Id = 1;
            [FieldOffset(2)] byte Version = 0;
            [FieldOffset(3)] byte Channel = 0;
            [FieldOffset(4)] byte Level = 4;
            [FieldOffset(5)] byte Opcode = 0;
            [FieldOffset(6)] ushort Task = 0;
            [FieldOffset(8)] long Keyword = 0;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct EVENT_DATA_DESCRIPTOR
        {
            [FieldOffset(0)]
            internal UInt64 DataPointer;
            [FieldOffset(8)]
            internal uint Size;
            [FieldOffset(12)]
            internal int Reserved;
        }

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern WINERROR EventRegister(ref Guid guid, [Optional] IntPtr EnableCallback, [Optional] IntPtr CallbackContext, [In][Out] ref ulong RegHandle);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern unsafe WINERROR EventWrite(ulong RegHandle, ref EVENT_DESCRIPTOR EventDescriptor, uint UserDataCount, EVENT_DATA_DESCRIPTOR* UserData);

        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern WINERROR EventUnregister(ulong RegHandle);
    }
}