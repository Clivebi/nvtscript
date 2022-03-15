if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104168" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Nmap NSE net: p2p-conficker" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Checks if a host is infected with Conficker.C or higher, based on Conficker's peer to peer
communication.

When Conficker.C or higher infects a system, it opens four ports: two TCP and two UDP. The ports are
random, but are seeded with the current week and the IP of the infected host. By determining the
algorithm, one can check if these four ports are open, and can probe them for more data.

Once the open ports are found, communication can be initiated using Conficker's custom peer to peer
protocol.  If a valid response is received, then a valid Conficker infection has been found.

This check won't work properly on a multihomed or NATed system because the open ports will be based
on a nonpublic IP.

SYNTAX:

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.

checkall:  If set to '1' or 'true', attempt
to communicate with every open port.

randomseed:    Set to a value to change the filenames/service names that are randomly generated.

checkconficker:  If set to '1' or 'true', the script will always run on active hosts,
it doesn't matter if any open ports were detected.

smbbasic:     Forces the authentication to use basic security, as opposed to 'extended security'.

realip:  An IP address to use in place of the one known by Nmap.

smbsign:       Controls whether or not server signatures are checked in SMB packets. By default, on Windows,
server signatures aren't enabled or required. By default, this library will always sign
packets if it knows how, and will check signatures if the server says to. Possible values are:

  - 'force':      Always check server signatures, even if server says it doesn't support them (will
probably fail, but is technically more secure).

  - 'negotiate': [default] Use signatures if server supports them.

  - 'ignore':    Never check server signatures. Not recommended.

  - 'disable':   Don't send signatures, at all, and don't check the server's. not recommended." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

