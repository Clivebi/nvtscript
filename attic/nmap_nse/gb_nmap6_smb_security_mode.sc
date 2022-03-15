if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803514" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_cve_id( "CVE-2008-4037" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:03 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-security-mode" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "http://www.skullsecurity.org/blog/?p=110" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-068" );
	script_tag( name: "summary", value: "Returns information about the SMB security level determined by SMB.

Here is how to interpret the output:

  - User-level authentication: Each user has a separate username/password that is used to log into the
system. This is the default setup of pretty much everything these days.

  - Share-level authentication: The anonymous account should be used to log in, then the password is given (in
plaintext) when a share is accessed. All users who have access to the share use this password. This
was the original way of doing things, but isn't commonly seen, now. If a server uses share-level
security, it is vulnerable to sniffing.

  - Challenge/response passwords supported: If enabled, the server can accept any type of password (plaintext, LM and NTLM, and LMv2 and NTLMv2).  If it isn't
set, the server can only accept plaintext passwords. Most servers are configured to use
challenge/response these days. If a server is configured to accept plaintext passwords, it is
vulnerable to sniffing. LM and NTLM are fairly secure, although there are some brute-force attacks
against them. Additionally, LM and NTLM can fall victim to man-in-the-middle attacks or relay
attacks (see MS08-068 or the referenced writeup of it.).

  - Message signing: If required, all messages between the client and server must be signed by a shared key,
derived from the password and the server challenge. If supported and not required, message signing
is negotiated between clients and servers and used if both support and request it. By default,
Windows clients don't sign messages, so if message signing isn't required by the server, messages
probably won't be signed. Additionally, if performing a man-in-the-middle attack, an attacker can
negotiate no message signing. If message signing isn't required, the server is vulnerable to man-in-
the-middle attacks or SMB-relay attacks.

This script will allow you to use the 'smb*' script arguments (to set the username and
password, etc.), but it probably won't ever require them.

SYNTAX:

smbbasic:     Forces the authentication to use basic security, as opposed to 'extended security'.
Against most modern systems, extended security should work, but there may be cases
where you want to force basic. There's a chance that you'll get better results for
enumerating users if you turn on basic authentication.

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.

smbsign:       Controls whether or not server signatures are checked in SMB packets. By default, on Windows,
server signatures aren't enabled or required. By default, this library will always sign
packets if it knows how, and will check signatures if the server says to. Possible values are:

  - 'force':      Always check server signatures, even if server says it doesn't support them (will
probably fail, but is technically more secure).

  - 'negotiate': [default] Use signatures if server supports them.

  - 'ignore':    Never check server signatures. Not recommended.

  - 'disable':   Don't send signatures, at all, and don't check the server's. not recommended.
More information on signatures can be found in 'smbauth.lua'.

randomseed:    Set to a value to change the filenames/service names that are randomly generated." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

