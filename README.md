# Log-Analysis-Sysmon
Analyzing Sysmon logs to detect and investigate malicious activities, with examples from Blue Team Labs Online challenges

Go to Blue team Labs online website and open the lab : [Log Analysis - Sysmon](https://blueteamlabs.online/home/challenge/log-analysis-sysmon-fabcb83517)
Download the file. We have to investigate the sysmon logs & answer some of the questions related to it.

**1. What is the file that gave access to the attacker?**

Inspect logs, see if you find any suspicious event, weird commands for this use the filter 
```
source="sysmon-events.json" | stats count by Event.EventData.CommandLine 
```

You will find alot of suspicious commands, some of them trying to establish connection to C2 server, some downloading malcious file from internet, some executing malicious code using powershell in hidden window. you will see powershell.exe, supply.exe , but we have to find who started this process, for this use the filter. 

```
source="sysmon-events.json"| stats count by Event.EventData.CommandLine Event.EventData.ProcessId Event.EventData.ParentProcessId
```
the very first command we found suspicious is powershell.exe which running a code in hidden window, the Parent process ID is 2848, which is associated to updater.hta,  HTA files are essentially HTML files that are executed using the Microsoft HTML Application Host (mshta.exe). we can assume that updater.hta may have some malicious embedded hidden code in it which execute malicious command in powershell.

**answer : updater.hta**

**2. What is the powershell cmdlet used to download the malware file and what is the port?**

Use the same filter to find the command, you will see the powershell command the the cmdlet used.
![powershell](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/qdxtpmv25zxkpp30sui4.png)

**answer: INvoke-WebRequest 6969**

**3. What is the name of the environment variable set by the attacker?**

filter: 
```
source="sysmon-events.json"| stats count by Event.EventData.CommandLine
```
![variable set](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ygh6knac35v2kg332tga.png)

**answer: comspec=C:\windows\temp\supply.exe**

**4.What is the process used as a LOLBIN to execute malicious commands?**

A LOLBIN (Living Off The Land Binary) refers to a legitimate, trusted executable or tool that is already present on the system. Attackers abuse these binaries to execute malicious commands or payloads, reducing the likelihood of detection by security software.
Common examples of LOLBINs include PowerShell, cmd.exe, ftp.exe, and wscript.exe, which are integral to the operating system.
In this case it could be powershell.exe or ftp.exe, because all malicious activity was started with powershell command it also downloads malicious file from internet like supply.exe, but in some instances of supply.exe the parent process is ftp.exe. 

**the correct answer according to the lab is ftp.exe**

**5. Malware executed multiple same commands at a time, what is the first command executed?**

![malicious command](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/8vd76qjvqnqkzhsi73no.png)

**answer: ipconfig**

**6. Looking at the dependency events around the malware, can you able to figure out the language, the malware is written.** 

filter: 
```
`source="sysmon-events.json" | stats count by Event.EventData.TargetFilename Event.EventData.Image`
```
![dependencies used by supply.exe](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/bfcv9bd4p248cacfsh35.png)
supply.exe targets 2 dynamic-linked libraries: Python27.dll & msvcr90.dll. Python27.dll indicating that the malware likely includes or relies on Python code. msvcr90.dll is microsoft visual C++ Runtime 9.0 library, It suggests that the Python interpreter or the malware itself was compiled or linked with Visual C++.

**answer: python**

**7. Malware then downloads a new file, find out the full url of the file download.** 

filter: `source="sysmon-events.json" | stats count by Event.EventData.CommandLine `
![file download powershell command](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/87wzu7in5xsrndmzc7ny.png)

**answer:** 
```
https://github.com/ohpe/juicypotato/releases/download/v0.1/JuicyPotato.exe
```
**8. What is the port the attacker attempts to get reverse shell?** 

Reverse shell mean when attacker establishes a backdoor connection from the infected system to the attacker's Command and Control (C2) server, enabling the attacker to execute commands on the infected machine and potentially exfiltrate sensitive information.

![reverse shell command](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/sxn7dgt0cd5az51137nm.png)

supply.exe execute the command juicy.exe is likely a tool that exploits privilege escalation vulnerabilities, sets a local listner on port 9999. establish a connection to the attacker's machine at IP 192.168.1.11, port 9898. question is asking for the destination port (attacker's system port).

**answer: 9898**

