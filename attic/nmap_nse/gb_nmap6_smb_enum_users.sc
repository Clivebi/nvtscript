if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803536" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:25 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-enum-users" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Attempts to enumerate the users on a remote Windows system, with as much information as possible,
through two different techniques (both over MSRPC, which uses port 445 or 139. See 'smb.lua'). The goal of this script is to discover all user accounts that exist on a
remote system. This can be helpful for administration, by seeing who has an account on a server, or
for  penetration testing or network footprinting, by determining which accounts  exist on a system.

A penetration tester who is examining servers may wish to determine the purpose of a server. By
getting a list of who has access to it, the tester might get a better idea (if financial people have
accounts, it probably  relates to financial information). Additionally, knowing which accounts exist
on a system (or on multiple systems) allows the pen-tester to build a dictionary of possible
usernames for bruteforces, such as a SMB bruteforce or a Telnet bruteforce. These accounts may be
helpful for other purposes, such as using the accounts in Web applications on this or other
servers.

From a pen-testers perspective, retrieving the list of users on any  given server creates endless
possibilities.

Users are enumerated in two different ways:  using SAMR enumeration or  LSA bruteforcing. By
default, both are used, but they have specific advantages and disadvantages. Using both is a great
default, but in certain circumstances it may be best to give preference to one.

Advantages of using SAMR enumeration:

  - Stealthier (requires one packet/user account, whereas LSA uses at least 10 packets while SAMR uses half that. Additionally, LSA makes a lot of noise in the
Windows event log (LSA enumeration is the only script I (Ron Bowes) have been called on by the
administrator of a box I was testing against).

  - More information is returned (more than just the username).

  - Every account will be found, since they're being enumerated with a function that's designed to enumerate users.

SYNTAX:

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.

randomseed:    Set to a value to change the filenames/service names that are randomly generated.

lsaonly:  If set, script will only enumerate using an LSA bruteforce (requires less
access than samr). Only set if you know what you're doing, you'll get better results
by using the default options.

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

samronly:  If set, script will only query a list of users using a SAMR lookup. This is
much quieter than LSA lookups, so enable this if you want stealth. Generally, however,
you'll get better results by using the default options." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

