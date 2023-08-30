<h1 align="center">Sysmon Utility MITRE ATT&CK :zap:</h1>



## Investigate Attack Patterns using SIEM, Sysmon Utility and MITRE ATT&CK

### Investigate SIEM logs with Sysmon System Utility

***Sysmon is a utility used for Windows and Linux system monitoring. It collects information related to file system activity, program execution, the hash of an executable, and more.***

***After installation, it will log additional executable information to Windows Events, and the events will be collected by Splunk Forwarder and sent to the Splunk server. Events collected by Sysmon help us analyze attack patterns, including the action performed by an executable.***

```
Sysmon64 can be installed via Sysmon64.exe -i
```

***Usage
Common usage featuring simple command-line options to install and uninstall Sysmon, as well as to check and modify its configuration:***

```
Install: sysmon64 -i [<configfile>]
Update configuration: sysmon64 -c [<configfile>]
Install event manifest: sysmon64 -m
Print schema: sysmon64 -s
Uninstall: sysmon64 -u [force]
```
### _Sysmon Paramets_

	Parameter		Description
	-i				Install service and driver. Optionally take a configuration file.
	-c				Update configuration of an installed Sysmon driver or dump the current configuration if no other argument is provided. Optionally takes a configuration file.
	-m				Install the event manifest (implicitly done on service install as well).
	-s				Print configuration schema definition.
	-u				Uninstall service and driver. Using -u force causes uninstall to proceed even when some components are not installed.

***Install with default settings (process images hashed with SHA1 and no network monitoring)***

```sysmon -accepteula -i```

***Install Sysmon with a configuration file (as described below)***

```sysmon -accepteula -i c:\windows\config.xml```

***Uninstall***

```sysmon -u```

***Dump the current configuration***

sysmon -c


***Reconfigure an active Sysmon with a configuration file (as described below)***

```sysmon -c c:\windows\config.xml```


***Change the configuration to default settings***
```
sysmon -c --
```

***Show the configuration schema***
```
sysmon -s
```

***Events
On Vista and higher, events are stored in Applications and Services ``Logs/Microsoft/Windows/Sysmon/Operational``, and on older systems events are written to the System event log. Event timestamps are in UTC standard time.***
***

### _The following are examples of each event type that Sysmon generates._
***
***Event ID 1: Process creation The process creation event provides extended information about a newly created process.
The full command line provides context on the process execution. The ProcessGUID field is a unique value for this process across a domain to make event correlation easier.The hash is a full hash of the file with the algorithms in the HashType field.***
***

***Event ID 2: A process changed a file creation time
The change file creation time event is registered when a file creation time is explicitly modified by a process. This event helps tracking the real creation time of a file. Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system. Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.***
***

***Event ID 3: Network connection
The network connection event logs TCP/UDP connections on the machine. It is disabled by default. Each connection is linked to a process through the ProcessId and ProcessGuid fields. The event also contains the source and destination host names IP addresses, port numbers and IPv6 status.***
***

***Event ID 4: Sysmon service state changed
The service state change event reports the state of the Sysmon service (started or stopped).***
***
***Event ID 5: Process terminated
The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId of the process.***
***
***Event ID 6: Driver loaded
The driver loaded events provides information about a driver being loaded on the system. The configured hashes are provided as well as signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading.***
***
***Event ID 7: Image loaded
The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the "–l" option. It indicates the process in which the module is loaded, hashes and signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading. This event should be configured carefully, as monitoring all image load events will generate a significant amount of logging.***
***
***Event ID 8: CreateRemoteThread
The CreateRemoteThread event detects when a process creates a thread in another process. This technique is used by malware to inject code and hide in other processes. The event indicates the source and target process. It gives information on the code that will be run in the new thread: StartAddress, StartModule and StartFunction. Note that StartModule and StartFunction fields are inferred, they might be empty if the starting address is outside loaded modules or known exported functions.***
***
***Event ID 9: RawAccessRead
The RawAccessRead event detects when a process conducts reading operations from the drive using the \\.\ denotation. This technique is often used by malware for data exfiltration of files that are locked for reading, as well as to avoid file access auditing tools. The event indicates the source process and target device.***
***
***Event ID 10: ProcessAccess
The process accessed event reports when a process opens another process, an operation that’s often followed by information queries or reading and writing the address space of the target process. This enables detection of hacking tools that read the memory contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash attacks. Enabling it can generate significant amounts of logging if there are diagnostic utilities active that repeatedly open processes to query their state, so it generally should only be done so with filters that remove expected accesses.***
***
***Event ID 11: FileCreate
File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection.***
***
***Event ID 12: RegistryEvent (Object create and delete)
Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations, or specific malware registry modifications.***
***

### Sysmon uses abbreviated versions of Registry root key names, with the following mappings:


	Key name									Abbreviation
	HKEY_LOCAL_MACHINE							HKLM
	HKEY_USERS									HKU
	HKEY_LOCAL_MACHINE\System\ControlSet00x		HKLM\System\CurrentControlSet
	HKEY_LOCAL_MACHINE\Classes					HKCR

***
***Event ID 13: RegistryEvent (Value Set)
This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD.***
***
***Event ID 14: RegistryEvent (Key and Value Rename)
Registry key and value rename operations map to this event type, recording the new name of the key or value that was renamed.***
***
***Event ID 15: FileCreateStreamHash
This event logs when a named file stream is created, and it generates events that log the hash of the contents of the file to which the stream is assigned (the unnamed stream), as well as the contents of the named stream. There are malware variants that drop their executables or configuration settings via browser downloads, and this event is aimed at capturing that based on the browser attaching a Zone.Identifier "mark of the web" stream.***
***
***Event ID 16: ServiceConfigurationChange
This event logs changes in the Sysmon configuration - for example when the filtering rules are updated.***
***
***Event ID 17: PipeEvent (Pipe Created)
This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication.***
***
***Event ID 18: PipeEvent (Pipe Connected)
This event logs when a named pipe connection is made between a client and a server.***

***Event ID 19: WmiEvent (WmiEventFilter activity detected)
When a WMI event filter is registered, which is a method used by malware to execute, this event logs the WMI namespace, filter name and filter expression.***
***
***Event ID 20: WmiEvent (WmiEventConsumer activity detected)
This event logs the registration of WMI consumers, recording the consumer name, log, and destination.***
***
***Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
When a consumer binds to a filter, this event logs the consumer name and filter path.***
***
***Event ID 22: DNSEvent (DNS query)
This event is generated when a process executes a DNS query, whether the result is successful or fails, cached or not. The telemetry for this event was added for Windows 8.1 so it is not available on Windows 7 and earlier.***
***
***Event ID 23: FileDelete (File Delete archived)
A file was deleted. Additionally to logging the event, the deleted file is also saved in the ArchiveDirectory (which is C:\Sysmon by default). Under normal operating conditions this directory might grow to an unreasonable size - see event ID 26: FileDeleteDetected for similar behavior but without saving the deleted files.***
***
***Event ID 24: ClipboardChange (New content in the clipboard)
This event is generated when the system clipboard contents change.***
***
***Event ID 25: ProcessTampering (Process image change)
This event is generated when process hiding techniques such as "hollow" or "herpaderp" are being detected.***
***
***Event ID 26: FileDeleteDetected (File Delete logged)
A file was deleted.***
***
***Event ID 27: FileBlockExecutable
This event is generated when Sysmon detects and blocks the creation of executable files (PE format).***
***
***Event ID 28: FileBlockShredding
This event is generated when Sysmon detects and blocks file shredding from tools such as SDelete.***
***
***Event ID 29: FileExecutableDetected
This event is generated when Sysmon detects the creation of a new executable file (PE format).***
***
***Event ID 255: Error
This event is generated when an error occurred within Sysmon. They can happen if the system is under heavy load and certain tasks could not be performed or a bug exists in the Sysmon service, or even if certain security and integrity conditions are not met. You can report any bugs on the Sysinternals forum or over Twitter.***


# ***Hunting Step-By-Steps***

***Part 1: Look for a Web Browser Password Viewer executable and its Company attribute
Event ID 7: Image loaded events logged by Sysmon
According to Microsoft documentation, Sysmon Event ID 7 refers to the Image loaded by the operating system. It contains information, including the hash and signature information of an executable.***


>### Event ID 7: Image loaded

***The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the "–l" option. It indicates the process in which the module is loaded, hashes and signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading. This event should be configured carefully, as monitoring all image load events will generate a significant amount of logging.***

***Splunk Query Statement: 
```
“sysmon SignatureStatus=Unavailable AND browser”
```
***Using the Splunk Query: 
```
“sysmon SignatureStatus=Unavailable AND browser”
```
***we can identify executables without proper digital signature with the keyword “browser” included in the description of the executable file.***



***Part 2: Look for the original file name of an executable
OriginalFileName information logged by Sysmon
Using the same Splunk query searching for executables without a valid digital signature trusted by the Windows operating system, we can notice that there are several events containing the field ``“OriginalFileName”``.***


***According to Microsoft’s article, OriginalFileName is a field for reporting the original file name executed by a process.***

***Sysmon v10.0, Autoruns v13.95, VMMap v3.26
Sysmon 10.0
This release of Sysmon adds DNS query logging, reports OriginalFileName in process create and load image events, adds ImageName to named pipe events, logs pico process creates and terminates, and fixes several bugs. Autoruns 13.95
This Autoruns update adds support for user Shell folders redirections.   VMMap 3.26
This update to VMMap, a tool for looking at the virtual and physical memory usage of a process, fixes a bug in 64-bit CLR heap reporting.***


******As there are several events with the field ``“OriginalFileName”`` containing executables, we can look at each event individually to determine any suspicious activity.***

***Investigate ``OriginalFileName`` Property
To begin with, look at the first item, The ``OriginalFileName`` value matches the image name. We can put that aside and continue looking for other events.***


***Part 3: Identify the suspicious executable attempts to connect to which ``IP`` address
Event ID 3: Network connection information logged by ``Sysmon``
According to ``Sysmon`` documentation, Event ID 3 records the Network Connection activity that a process performs. Therefore, we know that we can add ``“Event ID 3”`` to filter for events related to network connection by the suspicious application.***


***Event ID 3: Network connection
The network connection event logs ``TCP/UDP`` connections on the machine. It is disabled by default. Each connection is linked to a process through the ``ProcessId`` and ``ProcessGuid`` fields. The event also contains the source and destination host names ``IP`` addresses, port numbers and ``IPv6`` status.***


***Exaample:***
```
Splunk Query Statement: “sysmon file.exe EventCode=3”
```
***"find outbound connection"***



***Part 4: Identify the suspicious executable attempts to change what registry key
``Event ID 12: RegistryEvent (Object create and delete)`` information logged by ``Sysmon``
According to ``Sysmon`` documentation, Event ID 12 records the events related to a process changing Windows Registry values. Therefore, we know that we can add ``“Event ID 12” ``to filter for events related to changes in registry key.***



***``Event ID 12: RegistryEvent`` (Object create and delete)
Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations, or specific ``malware`` registry modifications.***

Example: Splunk Query Statement: “sysmon file.exe EventCode=12”


***an example that's show one of the executable file change registry:***

It is found that the event path of the registry change is 
```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\
```


***Part 5: Identify binaries removed by the malicious executable
``Splunk`` Query Statement: ``“sysmon taskkill /im”``
Here we look for any events logged by ``Sysmon`` related to killing a task and deleting a file.***


***Part 6: Find out the command executed to change the behaviour of Windows Defender
Splunk Query Statement: ``“sysmon`` defender ``powershell”``***

***A command was logged by Sysmon, which is:***

***powershell 
```
WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender
``
PATH MSFT_MpPreference call Add ``ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True
```


***Part 7: Find out IDs set by the attacker
Splunk Query Statement: “sysmon defender ``‘Add ThreatIDDefaultAction_Ids’``***


***Part 8: Find out additional malicious binary and the DLLs loaded by the binary through MITRE ATT&CK technique
Event ID 7: Image loaded events logged by Sysmon***

***Going back to the events which match Sysmon Event ID 7: Image Loaded, for example the executable is“Easyfile.exe” was marked alongside`` “11111.exe”`` by ``Sysmon`` as ``“DLL Side-Loading.”``***


***Event ID 7: Image loaded
The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the "–l" option. It indicates the process in which the module is loaded, hashes and signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading. This event should be configured carefully, as monitoring all image load events will generate a significant amount of logging.***


***Splunk Query Statement: ``sysmon SignatureStatus=Unavailable RuleName=”technique_id=T1073,technique_name=DLL Side-Loading”``***

#### _for example:_

***From the query result, we know that the binary path C:\Users\Finance01\AppData\Roaming\Easyfile\Easyfile.exe refers to the file demonstrating the behaviour of DLL side-loading, which is a technique described by MITRE and detected by Sysmon.

The DLLs that loaded from the Easyfile.exe binary can be found under the ``ImageLoaded`` attribute as well, which were ``ffmpeg.dll, nw_elf.dll, nw.dll.``***


``DLL Side-loading technique description by MITRE``

***Hijack Execution Flow: DLL Search Order Hijacking
Other sub-techniques of Hijack Execution Flow (12)
Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. [1][2] Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.***

***There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, [3] by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program.[4] Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. [5]***

***Adversaries may also directly modify the search order via DLL redirection, which after being enabled (in the Registry and creation of a redirection file) may cause a program to load a different DLL.[6][7][8]***

***If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.***


### _sysmon config:_
```
https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
```
