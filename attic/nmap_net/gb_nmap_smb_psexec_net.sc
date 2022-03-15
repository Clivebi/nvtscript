if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104148" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: smb-psexec" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "This script implements remote process execution similar to the
Sysinternals' psexec tool, allowing a user to run a series of programs on a
remote machine and read the output. This is great for gathering information
about servers, running the same tool on a range of  system, or even
installing a backdoor on a collection of computers.

SYNTAX:

randomseed:    Set to a value to change the filenames/service names that are
randomly generated.

str:     The string go cipher/uncipher.

nocipher:  Set to '1' or 'true' to disable the ciphering of the returned text
(useful for debugging).

nocleanup:  If set to '1' or 'true', don't clean up at all. This leaves the
files on the remote system and the wrapper service installed.

share:    Set to override the share used for uploading. This also stops shares
from being enumerated, and all other shares will be ignored. No checks are done
to determine whether or not this is a valid share before using it. Requires
'sharepath' to be set.

sharepath:  The full path to the share (eg, 'c:\\windows'). This is required when creating a service.

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139.

nohide:   Don't set the uploaded files to hidden/system/etc.

key:      Script uses this value instead of a random encryption key (useful for debugging the crypto).

time:     The minimum amount of time, in seconds, to wait for the external module to finish (default:'15')

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

config:  The config file for this host (stores the encryption key).

cleanup:  Set to '1' or 'true' to simply clean up any mess we made (leftover
files, processes, etc. on the host OS)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

