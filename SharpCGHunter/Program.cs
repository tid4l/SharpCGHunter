using System;
using System.Management;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.Collections.Concurrent;


namespace SharpCGHunter
{
    
    class Program { 
    
        public static string Sanitize(string v)
        {
            if (v == null)
                return "";

            string lastChar = v.Substring(v.Length - 1);
            string firstChar = v.Substring(0, 1);
            if (firstChar == lastChar)
            {
                if (lastChar == "'" || lastChar == '"'.ToString())
                    v = v.Trim(lastChar.ToCharArray());
            }
            return v;
        }

        private static BlockingCollection<string> GenerateList(string input)
        {
            string[] split;
            BlockingCollection<string> hosts = new BlockingCollection<string>();

            if (input.Contains(","))
            {
                if (input.Contains(", "))
                {
                    split = input.Split(',');
                    for (int i = 0; i < split.Length; i++)
                    {
                        split[i] = split[i].Trim(' ');
                    }
                }
                else
                {
                    split = input.Split(',');
                }
                foreach (var i in split)
                {
                    hosts.Add(i);
                }
            }
            else if (input.Contains("/") || input.Contains("*"))
            {
                split = input.Split('.');
                if (input.Contains("0/8") || (split[1] == "*" && split[2] == "*" && split[3] == "*"))
                {
                    for (int i = 1; i < 256; i++)
                    {
                        for (int j = 1; j < 256; j++)
                        {
                            for (int k = 1; k < 256; k++)
                            {
                                hosts.Add(split[0] + "." + i + "." + j + "." + k);
                            }
                        }
                    }
                }
                else if (input.Contains("0/16") || (split[2] == "*" && split[3] == "*"))
                {
                    for (int i = 1; i < 256; i++)
                    {
                        for (int j = 1; j < 256; j++)
                        {
                            hosts.Add(split[0] + "." + split[1] + "." + i + "." + j);
                        }
                    }
                }
                else if (input.Contains("0/24") || split[3] == "*")
                {
                    for (int i = 1; i < 256; i++)
                    {
                        hosts.Add(split[0] + "." + split[1] + "." + split[2] + "." + i);
                    }
                }

            }
            else
            {
                hosts.Add(input);
            }
            return hosts;
        }

        private static BlockingCollection<string> EnumerateDomain(string input)
        {
            BlockingCollection<string> hosts = new BlockingCollection<string>();

            DirectoryEntry directoryEntry = new DirectoryEntry("LDAP://" + input);
            SearchResultCollection results;
            DirectorySearcher directorySearcher = null;

            directorySearcher = new DirectorySearcher(directoryEntry);

            directorySearcher.Filter = "(&(objectCategory=Computer))";
            directorySearcher.ReferralChasing = ReferralChasingOption.All;
            directorySearcher.PageSize = 1000;

            results = directorySearcher.FindAll();

            int i = 0;
            foreach (SearchResult searchResult in results)
            {
                string name = searchResult.Properties["name"][0].ToString();
                hosts.Add(name);
                i++;
            }

            Console.WriteLine("[+] {0} : Found {1} domain computers.\n", input, i);
            return hosts;
        }

        private static int CompareIPs(string x, string y)
        {
            if (x == null)
            {
                if (y == null)
                {
                    return 0;
                }
                else
                {
                    return 1;
                }
            }
            else
            {
                if (y == null)
                {
                    return -1;
                }
                else
                {
                    string[] xSplit = x.Split('.');
                    string[] ySplit = y.Split('.');

                    if (int.Parse(xSplit[3]) > int.Parse(ySplit[3])){
                        return 1;
                    }

                    else if (int.Parse(xSplit[3]) == int.Parse(ySplit[3])){
                        if (int.Parse(xSplit[2]) > int.Parse(ySplit[2]))
                        {
                            return 1;
                        }

                        else if (int.Parse(xSplit[2]) == int.Parse(ySplit[2]))
                        {
                            if (int.Parse(xSplit[1]) > int.Parse(ySplit[1]))
                            {
                                return 1;
                            }
                            else if (int.Parse(xSplit[1]) == int.Parse(ySplit[1]))
                            {
                                if (int.Parse(xSplit[0]) > int.Parse(ySplit[0]))
                                {
                                    return 1;
                                }
                                else
                                {
                                    return -1;
                                }

                            }
                            else
                            {
                                return -1;
                            }
                        }
                        else
                        {
                            return -1;
                        }
                    }
                    else
                    {
                        return -1;
                    }
                }
            }
        }

        private static string VbsStatus(char c)
        {
            if (c == '0')
            {
                return "Not enabled.";
            }
            else if (c == '1')
            {
                return "Enabled, not running.";
            }
            else if (c == '2')
            {
                return "Enabled and running.";
            }
            else
            {
                return "Unknown.";
            }
        }

        public static void Banner()
        {
            Console.WriteLine(@"
 _____ _                      _____ _____  _   _             _            
/  ___| |                    /  __ \  __ \| | | |           | |           
\ `--.| |__   __ _ _ __ _ __ | /  \/ |  \/| |_| |_   _ _ __ | |_ ___ _ __ 
 `--. \ '_ \ / _` | '__| '_ \| |   | | __ |  _  | | | | '_ \| __/ _ \ '__|
/\__/ / | | | (_| | |  | |_) | \__/\ |_\ \| | | | |_| | | | | ||  __/ |   
\____/|_| |_|\__,_|_|  | .__/ \____/\____/\_| |_/\__,_|_| |_|\__\___|_|   
                       | |                                                
                       |_|   

");
        }

        public static void Help()
        {
            Console.WriteLine(@"Usage:
SharpCGHunter.exe --host=127.0.0.1
SharpCGHunter.exe --domain=net.local

Required Arguments:
NONE            -Not specifying any arguments will execute it on the current host.

Optional Arguments:
--host=         -Specify a single remote host, a list of comma-seperated hosts, or an IP with wildcards/CIDR notations. 
                 A single host argument or comma-seperated host arguments can either be IPs or host names.
                 (I.E. --host=192.168.1.1,192.168.1.2 // --host=192.168.1.0/24 // --host=192.168.1.*)

--domain=       -Specify the domain and the program will enumerate domain systems and query them for Credential Guard.
                 (I.E. --domain=TARGET.LOCAL // --domain=TARGET)

--help          - Print help information.
");
        }

        static void Main(string[] args)
        {
            Banner();
            
            BlockingCollection<String> hosts = new BlockingCollection<String>();

            List<String> unprotectedHost = new List<String>();
            List<String> configuredHost = new List<String>();
            List<String> protectedHost = new List<String>();

            foreach (var arg in args)
            {
                if (arg.StartsWith("--host"))
                {
                    string[] components = arg.Split(new string[] { "--host=" }, StringSplitOptions.None);
                    
                    components[1] = Sanitize(components[1]); 
                    hosts = GenerateList(components[1]);
                }
                else if (arg.StartsWith("--domain"))
                {
                    string[] components = arg.Split(new string[] { "--domain=" }, StringSplitOptions.None);

                    var domain = Sanitize(components[1]);
                    hosts = EnumerateDomain(domain);
                }
                else if (arg.StartsWith("--help"))
                {
                    Help();
                    return;
                }
            }
            if (args.Length == 0)
            {
                hosts.Add(".");
            }

            var options = new ParallelOptions { MaxDegreeOfParallelism = 1000 };

            Parallel.ForEach(hosts, options, host =>
            {
                string Namespace = "\\\\" + host + "\\root\\Microsoft\\Windows\\DeviceGuard";
                var scope = new ManagementScope(Namespace);

                var outputHost = host;
                if (host == ".")
                {
                    outputHost = "localhost";
                }

                try
                {
                    scope.Connect();
                    var query = new ObjectQuery("SELECT * FROM Win32_DeviceGuard");
                    ManagementObjectCollection info;

                    ManagementObjectSearcher oSearch = new ManagementObjectSearcher(@scope, query);
                    info = oSearch.Get();

                    foreach (var result in info)
                    {
                        var config = (int[])result.GetPropertyValue("SecurityServicesConfigured");
                        var running = (int[])result.GetPropertyValue("SecurityServicesRunning");
                        uint? vbs = (uint)result.GetPropertyValue("VirtualizationBasedSecurityStatus");

                        if (config[0] == 1 && running[0] == 1)
                        {
                            Console.WriteLine("[-] {0} : Credential Guard is running.", outputHost);
                            protectedHost.Add(outputHost + "." + vbs.ToString());
                        }
                        else if (config[0] == 1 && running[0] != 1)
                        {
                            Console.WriteLine("[+] {0} : Credential Guard has been configured, but is not running.", outputHost);
                            configuredHost.Add(outputHost + "." + vbs.ToString());
                        }
                        else
                        {
                            Console.WriteLine("[+] {0} : Credential Guard is not configured or running.", outputHost);
                            unprotectedHost.Add(outputHost + "." + vbs.ToString());
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("[-] {0} : Error connecting.", outputHost);
                } 
            });

            Console.WriteLine("\n\n-SharpCGHunter Results Summary-\n");

            Console.WriteLine("Unprotected Hosts:\n");

            if (unprotectedHost.Count == 0)
            {
                Console.WriteLine("[-] None found.\n");
            }
            else
            {
                try
                {
                    unprotectedHost.Sort(CompareIPs);
                }
                catch (Exception) { }

                foreach (var i in unprotectedHost)
                {
                    var status = VbsStatus(i[i.Length - 1]);
                    Console.WriteLine("[+] {0} :\n\tCredential Guard is not configured or running.\n\tVirtualization-based Security Status : {1}\n", i.Remove(i.Length - 2), status);
                }
            }
            
            Console.WriteLine("\nConfigured Hosts:\n");

            if (configuredHost.Count == 0)
            {
                Console.WriteLine("[-] None found.\n");
            }
            else
            {
                try
                {
                    configuredHost.Sort(CompareIPs);
                }
                catch (Exception) { }
                
                foreach (var i in configuredHost)
                {
                    var status = VbsStatus(i[i.Length - 1]);
                    Console.WriteLine("[+] {0} :\n\tCredential Guard has been configured, but is not running.\n\tVirtualization-based Security Status : {1}\n", i.Remove(i.Length - 2), status);
                }
            }
           
            Console.WriteLine("\nProtected Hosts:\n");

            if (protectedHost.Count == 0)
            {
                Console.WriteLine("[-] None found.\n");
            }
            else
            {
                try
                {
                    protectedHost.Sort(CompareIPs);
                }
                catch (Exception) { }

                foreach (var i in protectedHost)
                {
                    var status = VbsStatus(i[i.Length - 1]);
                    Console.WriteLine("[-] {0} :\n\tCredential Guard is running.\n\tVirtualization-based Security Status : {1}\n", i.Remove(i.Length - 2), status);
                }
            }
            Console.WriteLine("");
        }
    }
}
