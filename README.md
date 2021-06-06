# SharpCGHunter

#### This tool can be used to identify the status of Windows Defender Credential Guard on network hosts.

At a high level, Credential Guard is a Windows feature that protects the host's secrets using virtualization-based security.

SharpCGHunter will query local and remote hosts to determine if Credential Guard is enabled and whether it is currently running. This tool will also return the virtualization-based security status on the host. 

```

 _____ _                      _____ _____  _   _             _
/  ___| |                    /  __ \  __ \| | | |           | |
\ `--.| |__   __ _ _ __ _ __ | /  \/ |  \/| |_| |_   _ _ __ | |_ ___ _ __
 `--. \ '_ \ / _` | '__| '_ \| |   | | __ |  _  | | | | '_ \| __/ _ \ '__|
/\__/ / | | | (_| | |  | |_) | \__/\ |_\ \| | | | |_| | | | | ||  __/ |
\____/|_| |_|\__,_|_|  | .__/ \____/\____/\_| |_/\__,_|_| |_|\__\___|_|
                       | |
                       |_|


Usage:
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

```

### __Versions__

__0.0.2:__

- Added wildcard and CIDR notation to host argument

- Supports domain enumeration and querying

- Improved output with sorted results upon completion

__0.0.1:__

- Initial release

### __For reference:__

[Credential Guard: How it works](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)

[How to Verify if Device Guard is Enabled or Disabled in Windows 10](https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html)
