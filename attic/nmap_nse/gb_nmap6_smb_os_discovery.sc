if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803563" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:52 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-os-discovery" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "http://www.skullsecurity.org/blog/?p=76" );
	script_tag( name: "summary", value: "Attempts to determine the operating system, computer name, domain, workgroup, and current time over
the SMB protocol (ports 445 or 139). This is done by starting a session with the anonymous  account
(or with a proper user account, if one is given. It likely doesn't make a difference). In response
to a session starting, the server will send back all this information.

The following fields may be included in the output, depending on the  circumstances (e.g. the
workgroup name is mutually exclusive with domain and forest names) and the information available:

  - OS

  - Computer name

  - Domain name

  - Forest name

  - FQDN

  - NetBIOS computer name

  - NetBIOS domain name

  - Workgroup

  - System time

Some systems, like Samba, will blank out their name (and only send their domain).  Other systems
(like embedded printers) will simply leave out the information. Other systems will blank out various
pieces (some will send back 0 for the current time, for example).

Retrieving the name and operating system of a server is a vital step in targeting an attack against
it, and this script makes that retrieval easy. Additionally, if a penetration tester is choosing
between multiple targets, the time can help identify servers that are being poorly maintained (for
more information/random thoughts on using the time, see references).

Although the standard 'smb*' script arguments can be used, they likely won't change the
outcome in any meaningful way. However, 'smbnoguest' will speed up the script on targets
that do not allow guest access.

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
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

