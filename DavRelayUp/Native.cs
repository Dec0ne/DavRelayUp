using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DavRelayUp
{
    class Native
    {
        public enum BindMethod : uint
        {
            LDAP_AUTH_SIMPLE = 0x80,
            LDAP_AUTH_OTHERKIND = 0x86,
            LDAP_AUTH_SICILY = LDAP_AUTH_OTHERKIND | 0x0200,
            LDAP_AUTH_MSN = LDAP_AUTH_OTHERKIND | 0x0800,
            LDAP_AUTH_NTLM = LDAP_AUTH_OTHERKIND | 0x1000,
            LDAP_AUTH_DPA = LDAP_AUTH_OTHERKIND | 0x2000,
            LDAP_AUTH_NEGOTIATE = LDAP_AUTH_OTHERKIND | 0x0400,
            LDAP_AUTH_SSPI = LDAP_AUTH_NEGOTIATE,
            LDAP_AUTH_DIGEST = LDAP_AUTH_OTHERKIND | 0x4000,
            LDAP_AUTH_EXTERNAL = LDAP_AUTH_OTHERKIND | 0x0020
        }

        [StructLayout(LayoutKind.Sequential)]
        public sealed class LDAP_TIMEVAL
        {
            public int tv_sec;
            public int tv_usec;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public sealed class SEC_WINNT_AUTH_IDENTITY_EX
        {
            public int version;
            public int length;
            public string user;
            public int userLength;
            public string domain;
            public int domainLength;
            public string password;
            public int passwordLength;
            public int flags;
            public string packageList;
            public int packageListLength;
        }

        [DllImport("wldap32", EntryPoint = "ldap_connect", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern uint ldap_connect(IntPtr ld, LDAP_TIMEVAL timeout);

        [DllImport("wldap32", EntryPoint = "ldap_init", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr ldap_init(string hostname, uint port);

        [DllImport("wldap32", EntryPoint = "ldap_bind_s", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr ldap_bind_s(IntPtr ld, string dn, SEC_WINNT_AUTH_IDENTITY_EX cred, ulong method);

        [DllImport("wldap32", EntryPoint = "ldap_search_s", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr ldap_search_s(IntPtr ld, string base_dn, uint scope, string filter, string attrs, uint attrsonly, out IntPtr res);

    }
}
