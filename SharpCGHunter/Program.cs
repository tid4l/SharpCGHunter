using System;
using System.Management;
using System.Collections.Generic;


namespace SharpCGHunter
{
    
    class Program { 
    
        public static string SanitizeInput(string variable)
        {
            if (variable == null)
                return "";

            string lastChar = variable.Substring(variable.Length - 1);
            string firstChar = variable.Substring(0, 1);
            if (firstChar == lastChar)
            {
                if (lastChar == "'" || lastChar == '"'.ToString())
                    variable = variable.Trim(lastChar.ToCharArray());
            }
            return variable;
        }

        public static void PrintBanner()
        {
            Console.WriteLine(@"
==SharpCGHunter==

");
        }

        public static void PrintHelp()
        {
            Console.WriteLine(@"Usage:
SharpCGHunter.exe --host=127.0.0.1

Required Arguments:
NONE            -Not specifying any arguments will execute it on the current host.

Optional Arguments:
--host=         -Specify a single remote host or a list of comma-seperated hosts. Accepts IPs and host names.
                 (I.E. --host=192.168.1.1,192.168.1.2)

--help          - Print help information.
");
        }

        static void Main(string[] args)
        {
            PrintBanner();
            
            List<String> hosts = new List<String>();
            string[] split;

            foreach (var arg in args)
            {
                if (arg.StartsWith("--host"))
                {
                    string[] components = arg.Split(new string[] { "--host=" }, StringSplitOptions.None);
                    components[1] = SanitizeInput(components[1]);
                    if (components[1].Contains(","))
                    {
                        if (components[1].Contains(", "))
                        {
                            split = components[1].Split(',');
                            for (int i = 0; i < split.Length; i++) 
                            {
                                split[i] = split[i].Trim(' ');
                            }
                        } else
                        {
                            split = components[1].Split(',');
                        }
                        foreach (var i in split)
                        {
                            hosts.Add(i);
                        }
                    }
                    else
                    {
                        hosts.Add(components[1]);
                    }
                }
                else if (arg.StartsWith("--help"))
                {
                    PrintHelp();
                    return;
                }
            }
            if (args.Length == 0)
            {
                hosts.Add(".");
            }

            foreach (var host in hosts)
            {
                string NamespacePath = "\\\\" + host + "\\root\\Microsoft\\Windows\\DeviceGuard";
                var scope = new ManagementScope(NamespacePath);

                var outputHost = host;
                if (host == ".")
                {
                    outputHost = "localhost";
                }
                              
                try
                {
                    scope.Connect();
                }
                catch (Exception)
                {
                    Console.WriteLine("[-] {0} :\n\tError connecting.\n", outputHost);
                    continue;

                }

                var queryObj = new ObjectQuery("SELECT * FROM Win32_DeviceGuard");
                ManagementObjectCollection info;

                ManagementObjectSearcher oSearch = new ManagementObjectSearcher(@scope, queryObj);
                info = oSearch.Get();

                foreach (var result in info)
                {
                    var config = (int[])result.GetPropertyValue("SecurityServicesConfigured");
                    var running = (int[])result.GetPropertyValue("SecurityServicesRunning");
                    uint? vbs = (uint)result.GetPropertyValue("VirtualizationBasedSecurityStatus");

                    if (config[0] == 1 && running[0] == 1)
                    {
                        Console.WriteLine("[-] {0} :\n\tCredential Guard is running.", outputHost);
                    }
                    else if (config[0] == 1 && running[0] != 1)
                    {
                        Console.WriteLine("[!] {0} :\n\tCredential Guard has been configured, but is not running.", outputHost);
                    }
                    else
                    {
                        Console.WriteLine("[+] {0} :\n\tCredential Guard is not configured or running.", outputHost);
                    }

                    string vbsStatus;
                    if (vbs == 0)
                    {
                        vbsStatus = "Not enabled.";
                    }
                    else if (vbs == 1)
                    {
                        vbsStatus = "Enabled, not running.";
                    }
                    else if (vbs == 2)
                    {
                        vbsStatus = "Enabled and running.";
                    }
                    else
                    {
                        vbsStatus = "Unknown.";
                    }
                    Console.WriteLine("\tVirtualization-based Security Status : {0}\n", vbsStatus);
                }
            }
        }
    }
}
