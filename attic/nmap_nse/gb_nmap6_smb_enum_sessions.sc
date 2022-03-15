if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803534" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:23 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-enum-sessions" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Enumerates the users logged into a system either locally or through an SMB share. The local users
can be logged on either physically on the machine, or through a terminal services session.
Connections to a SMB share are, for example, people connected to fileshares or making RPC calls.
Nmap's connection will also show up, and is generally identified by the one that connected '0
seconds ago'.

From the perspective of a penetration tester, the SMB Sessions is probably the most useful part of
this program, especially because it doesn't require a high level of access. On, for  example, a file
server, there might be a dozen or more users connected at the same time. Based  on the usernames, it
might tell the tester what types of files are stored on the share.

Since the IP they're connected from and the account is revealed, the information here can also
provide extra targets to test, as well as a username that's likely valid on that target.
Additionally, since a strong username to ip correlation is given, it can be a boost to a social
engineering  attack.

Enumerating the logged in users is done by reading the remote registry (and therefore won't  work
against Vista, which disables it by default). Keys stored under 'HKEY_USERS' are  SIDs
that represent the connected users, and those SIDs can be converted to proper names by using  the
'lsar.LsaLookupSids' function. Doing this requires any access higher than anonymous then
guests, users, or administrators are all able to perform this request on Windows 2000, XP, 2003, and
Vista.

Enumerating SMB connections is done using the 'srvsvc.netsessenum' function, which
returns the usernames that are logged in, when they logged in, and how long they've been idle  for.
The level of access required for this varies between Windows versions, but in Windows  2000 anybody
account is required.

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

