# Exchange-HAFNIUM
Threat Advisory for the MS Exchange Zero-day Vulnerability

**Introduction**

On March 2, 2021 Microsoft has released patches for several critical vulnerabilities for Microsoft Exchange Server that have been found to be exploited in different regions. It is highly recommended for all the users running affected versions to update their servers with newly released patches in order to secure their environments.
 
The vulnerabilities affect Microsoft Exchange Server. Exchange Online is not affected.  

The versions affected are: 
Microsoft Exchange Server 2013  
Microsoft Exchange Server 2016  
Microsoft Exchange Server 2019 

**Threat Actor HAFNIUM**

Microsoft Threat Intelligence Center has attributed the attacks with high level of confidence to an adversary dubbed as HAFNIUM, a group known to be a state-sponsored and operating from China. The attribution is based on the knowledge about the tactics, procedures and study of victims of these attacks. 

Actor has been known to exploit the vulnerabilities existing in internet-facing servers using open source frameworks to compromise the systems and later exfiltrate the data. 

**Vulnerabilities**

There are total of four vulnerabilities that have been reported. These all have been classified as Critical and need to be updated at the earliest.

CVE-2021-26855 (CVSS:3.0 9.1) is a server-side request forgery (SSRF) vulnerability in Exchange which allowed the attacker to send arbitrary HTTP requests and authenticate as the Exchange server. This would also allow the attacker to gain access to mailboxes and read sensitive information

CVE-2021-26857 (CVSS:3.0 7.8) is an insecure deserialization vulnerability in the Unified Messaging service. Insecure deserialization is where untrusted user-controllable data is deserialized by a program. Exploiting this vulnerability gave HAFNIUM the ability to run code as SYSTEM on the Exchange server. This requires administrator permission or another vulnerability to exploit.

CVE-2021-26858 (CVSS:3.0 7.8) is a post-authentication arbitrary file write vulnerability in Exchange. If HAFNIUM could authenticate with the Exchange server then they could use this vulnerability to write a file to any path on the server. They could authenticate by exploiting the CVE-2021-26855 SSRF vulnerability or by compromising a legitimate admin’s credentials.

CVE-2021-27065 (CVSS:3.0 7.8) is a post-authentication arbitrary file write vulnerability in Exchange. If HAFNIUM could authenticate with the Exchange server then they could use this vulnerability to write a file to any path on the server. They could authenticate by exploiting the CVE-2021-26855 SSRF vulnerability or by compromising a legitimate admin’s credentials.

**Technical Details**

Volexity has observed different techniques and tactics used by the threat actors in different organizations. We are sharing those TTPs here for detection and remediation purposes. It has been observed that the attacker exploited these vulnerabilities and implanted the webshells on different folders in exchange servers which do not require the authentication. POST requests observed for targeting web directory are following:

**Malicious Directories**
1. /owa/auth/current/themes/resources
C:\inetpub\wwwroot\aspnet_client\
C:\inetpub\wwwroot\aspnet_client\system_web\
*exchange install path*\FrontEnd\HttpProxy\ecp\auth\ (Only TimeoutLogoff.aspx file should be present)
*exchange install path*\FrontEnd\HttpProxy\owa\auth\ (any non-standard file)

**WEB shells**
There are many web shells observed during the attacks and should be searched in the environment using the following query. Query needs to be tweaked according the tool being used for the investigation.

	Request Method: POST
	Request Path: <any of the below mentioned web shells>
	Response Status Code: 200

The web shells detected had the following file names: 

web.aspx
help.aspx
document.aspx
errorEE.aspx
errorEEE.aspx
errorEW.aspx
errorFF.aspx
healthcheck.aspx
aspnet_www.aspx
aspnet_client.aspx
xx.aspx
shell.aspx
aspnet_iisstart.aspx
one.aspx
<single character>.js


**Suspicious User Agents:**
Few of the suspicious user agents to be aware of while looking for the malicious behavior in environment are mentioned below:

ExchangeServicesClient/0.0.0.0
python-requests/2.19.1
python-requests/2.25.1

**Malicious IPs:**
Following IPs should be investigated for any malicious connections, however this is not a complete list since the exploit can be launched from any other IP.

103.77.192[.]219
104.140.114[.]110
104.250.191[.]110
108.61.246[.]56
149.28.14[.]163
157.230.221[.]198
167.99.168[.]251
185.250.151[.]72
192.81.208[.]169
203.160.69[.]66
211.56.98[.]146
5.254.43[.]18
5.2.69[.]14
80.92.205[.]81
91.192.103[.]43

**Investigation Tips**
We recommend checking the following for potential evidence of compromise:

Child processes of C:\Windows\System32\inetsrv\w3wp.exe on Exchange Servers, particularly cmd.exe.
Files written to the system by w3wp.exe or UMWorkerProcess.exe.
ASPX files owned by the SYSTEM user
New, unexpected compiled ASPX files in the Temporary ASP.NET Files directory
Reconnaissance, vulnerability-testing requests to the following resources from an external IP address:
/rpc/ directory
/ecp/DDI/DDIService.svc/SetObject
Non-existent resources
With suspicious or spoofed HTTP User-Agents
Unexpected or suspicious Exchange PowerShell SnapIn requests to export mailboxes


**Remediation**

The server needs be patched at the earliest and ensured that the system is secure. It can be remediated using a separate VPN for the exchange server, however it would be a temporary fix and will only block the initial access vector. If attacker is able to bypass it or has already access to network the vulnerability will be exploited. Furthermore, access to the /ecp/ and /owa/auth folder can be restricted for external users.

**References**

https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26857
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26858
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065
