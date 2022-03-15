if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104015" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: smb-enum-shares" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to list shares using the 'srvsvc.NetShareEnumAll' MSRPC function and retrieve
more information about them using 'srvsvc.NetShareGetInfo'. If access to those functions
is denied, a list of common share names are checked.

Finding open shares is useful to a penetration tester because there may be private files shared, or,
if it's writable, it could be a good place to drop a Trojan or to infect a file that's already
there. Knowing where the share is could make those kinds of tests more useful, except that
determiing where the share is requires administrative privileges already.

Running 'NetShareEnumAll' will work anonymously against Windows 2000, and  requires a
user-level account on any other Windows version. Calling 'NetShareGetInfo'  requires an
administrator account on all versions of Windows up to 2003, as well as Windows Vista and Windows 7,
if UAC is turned down.

Even if 'NetShareEnumAll' is restricted, attempting to connect to a share will always
reveal its existence. So, if 'NetShareEnumAll' fails, a pre-generated list of shares,
based on a large test network, are used. If any of those succeed, they are recorded.

After a list of shares is found, the script attempts to connect to each of them anonymously, which
divides them into 'anonymous', for shares that the NULL user can connect to, or 'restricted', for
shares that require a user account.

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

