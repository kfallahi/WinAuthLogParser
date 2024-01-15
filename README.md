# WinAuthLogParser


WinAuthLogParser is a powerful Digital Forensics and Incident Response tool designed specifically for analyzing Windows authentication Event Logs.
It works by parsing security events with IDs 4624 and 4625. It helps a lot in responding to incidents, allowing users to quickly and thoroughly understand security events on Windows systems.
It's not just for Incident Responders; it's useful for Red Team Operators and the whole InfoSec community, being a valuable asset on Windows platforms.

- As an **Incident Responder**, you can find and investigate all successful and failed logons.
- As a **Red Team Operator**, by finding successful logons on key users like domain admins, you can identify their personal systems within the target organization.

Below is a list of features that WinAuthLogParser can analyze:
- Hostname
- IP Address
- LogonType
- Process Name
- DateTime
- Domain/Workstation Name
- Failure Reason


## Usage

- Specify **Userlist** as a text file path containing usernames. By default, WinAuthLogParser analyzes all users.
- Specify **LogPath** as a path of security.evtx file. By default, WinAuthLogParser analyzes the live system security .evtx file.
- Specify **OutDir** for the output directory. Output is saved as a CSV file.

```
PS C:\> WinAuthLog-Parser -OutDir c:\temp\
PS C:\> WinAuthLog-Parser -OutDir c:\temp\ -LogPath c:\temp\security.evtx
PS C:\> WinAuthLog-Parser -OutDir c:\temp\ -UserList c:\temp\users.txt
PS C:\> WinAuthLog-Parser -OutDir c:\temp\ -LogPath c:\temp\security.evtx -UserList c:\temp\users.txt
```






