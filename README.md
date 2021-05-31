# SharpCGHunter

#### This tool can be used to identify the status of Windows Defender Credential Guard on network hosts.

At a high level, Credential Guard is a Windows feature that protects the host's secrets using virtualization-based security.

SharpCGHunter will query local and remote hosts to determine if Credential Guard is enabled and whether it is currently running. This tool will also return the virtualization-based security status on the host. 

```
==SharpCGHunter==


Usage:
SharpCGHunter.exe --host=127.0.0.1

Required Arguments:
NONE            -Not specifying any arguments will execute it on the current host.

Optional Arguments:
--host=         -Specify a single remote host or a list of comma-seperated hosts. Accepts IPs and host names.
                 (I.E. --host=192.168.1.1,192.168.1.2)

--help          - Print help information.
```


__For reference:__

[Credential Guard: How it works](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)

[How to Verify if Device Guard is Enabled or Disabled in Windows 10](https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html)
