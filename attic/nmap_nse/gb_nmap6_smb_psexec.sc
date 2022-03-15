if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803527" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:16 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-psexec" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Implements remote process execution similar to the Sysinternals' psexec tool, allowing a user to
run a series of programs on a remote machine and read the output. This is great for gathering
information about servers, running the same tool on a range of  system, or even installing a
backdoor on a collection of computers.

This script can run commands present on the remote machine, such as ping or tracert, or it can
upload a program and run it, such as pwdump6 or a backdoor. Additionally, it  can read the program's
stdout/stderr and return it to the user (works well with ping, pwdump6, etc), or it can read a file
that the process generated (fgdump, for example, generates a file), or it can just start the
process and let it run headless (a backdoor might run like this).

To use this, a configuration file should be created and edited. Several configuration files are
included that you can customize, or you can write your own. This config file  is placed in
'nselib/data/psexec' (if you aren't sure where that is, search your system  for
'default.lua'), then is passed to Nmap as a script argument (for example, myconfig.lua
would be passed as '--script-args=config=myconfig'.

The configuration file consists mainly of a module list. Each module is defined by a lua table, and
contains fields for the name of the program, the executable and arguments  for the program, and a
score of other options. Modules also have an 'upload' field, which determines whether or not the
module is to be uploaded. Here is a simple example of how  to run 'net localgroup
administrators', which returns a list of users in the 'administrators' group (take a look at
the 'examples.lua' configuration file for these examples):

'         mod = {}         mod.upload           = false         mod.name             = 'Example
1: Membership of 'administrators''         mod.program          = 'net.exe'         mod.args

SYNTAX:

randomseed:    Set to a value to change the filenames/service names that are randomly generated.

str:     The string go cipher/uncipher.

nocipher:  Set to disable the ciphering of the returned text (useful for debugging).

nocleanup:  Set to not clean up at all. This leaves the files on the remote system and the wrapper
service installed. This is bad in practice, but significantly reduces the network traffic and makes analysis
easier.

share:    Set to override the share used for uploading. This also stops shares from being enumerated, and all other shares
will be ignored. No checks are done to determine whether or not this is a valid share before using it. Reqires
'sharepath' to be set.

sharepath:  The full path to the share (eg, ''c:\\windows''). This is required when creating a service.

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.

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
More information on signatures can be found in 'smbauth.lua'.

config:  The config file for this host (stores the encryption key).

cleanup:  Set to only clean up any mess we made (leftover files, processes, etc. on the host OS) on a previous run of the script.
This will attempt to delete the files from every share, not just the first one. This is done to prevent leftover
files if the OS changes the ordering of the shares (there's no guarantee of shares coming back in any particular
order)
Note that cleaning up is still fairly invasive, since it has to re-discover the proper share, connect to it,
delete files, open the services manager, etc." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

