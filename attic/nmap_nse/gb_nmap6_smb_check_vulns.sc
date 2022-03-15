if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803571" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_cve_id( "CVE-2006-2370", "CVE-2006-2371", "CVE-2007-1748", "CVE-2008-4250", "CVE-2009-3103" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:01:00 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-check-vulns" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/975497" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-029" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-025" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067" );
	script_tag( name: "summary", value: "Checks for vulnerabilities:

  - MS08-067, a Windows RPC vulnerability

  - Conficker, an infection by the Conficker worm

  - Unnamed regsvc DoS, a denial-of-service vulnerability I accidentally found in Windows 2000

  - SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)

  - MS06-025, a Windows Ras RPC service vulnerability

  - MS07-029, a Windows Dns Server RPC service vulnerability

WARNING: These checks are dangerous, and are very likely to bring down a server.  These should not
be run in a production environment unless you (and, more importantly, the business) understand the
risks!

As a system administrator, performing these kinds of checks is crucial, because  a lot more damage
can be done by a worm or a hacker using this vulnerability than by a scanner. Penetration testers,
on the other hand, might not want to use this script -- crashing services is not generally a good
way of sneaking through a  network.

If you set the script parameter 'unsafe', then scripts will run that are almost  (or
totally) guaranteed to crash a vulnerable system. Do NOT specify 'unsafe' in a production
environment! And that isn't to say that non-unsafe scripts will  not crash a system, they're just
less likely to.

If you set the script parameter 'safe', then script will run that rarely or never crash a
vulnerable system. No promises, though.

MS08-067. Checks if a host is vulnerable to MS08-067, a Windows RPC vulnerability that can allow
remote code execution.  Checking for MS08-067 is very dangerous, as the check  is likely to crash
systems. On a fairly wide scan conducted by Brandon Enright, we determined that on average, a
vulnerable system is more likely to crash than to survive the check. Out of 82 vulnerable systems,

SYNTAX:

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.

randomseed:    Set to a value to change the filenames/service names that are randomly generated.

smbbasic:     Forces the authentication to use basic security, as opposed to 'extended security'.
Against most modern systems, extended security should work, but there may be cases
where you want to force basic. There's a chance that you'll get better results for
enumerating users if you turn on basic authentication.

smbsign:       Controls whether or not server signatures are checked in SMB packets. By default, on Windows,
server signatures aren't enabled or required. By default, this library will always sign
packets if it knows how, and will check signatures if the server says to. Possible values are:

  - 'force':      Always check server signatures, even if server says it doesn't support them (will
probably fail, but is technically more secure).

  - 'negotiate': [default] Use signatures if server supports them.

  - 'ignore':    Never check server signatures. Not recommended.

  - 'disable':   Don't send signatures, at all, and don't check the server's. not recommended.
More information on signatures can be found in 'smbauth.lua'.


safe:    If set, this script will only run checks that are known (or at
least suspected) to be safe.

unsafe:  If set, this script will run checks that, if the system isn't
patched, are basically guaranteed to crash something. Remember that
non-unsafe checks aren't necessarily safe either)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

