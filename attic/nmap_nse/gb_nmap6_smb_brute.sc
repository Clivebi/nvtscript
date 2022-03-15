if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803509" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 18:59:58 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smb-brute" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "http://www.skullsecurity.org/blog/?p=164" );
	script_xref( name: "URL", value: "http://www.skullsecurity.org/wiki/index.php/Passwords" );
	script_tag( name: "summary", value: "Attempts to guess username/password combinations over SMB, storing discovered combinations  for use
in other scripts. Every attempt will be made to get a valid list of users and to  verify each
username before actually using them. When a username is discovered, besides  being printed, it is
also saved in the Nmap registry so other Nmap scripts can use it. That means that if you're going to
run 'smb-brute.nse', you should run other 'smb' scripts you want.  This checks
passwords in a case-insensitive way, determining case after a password is found, for Windows
versions before Vista.

This script is specifically targeted towards security auditors or penetration testers.  One example
of its use, suggested by Brandon Enright, was hooking up 'smb-brute.nse' to the database
of usernames and passwords used by the Conficker worm (the password list can be found at the
references), among other places. Then, the network is
scanned and all systems that would be infected by Conficker are  discovered.

From the penetration tester perspective its use is pretty obvious. By discovering weak passwords on
SMB, a protocol that's well suited for bruteforcing, access to a system can be gained.  Further,
passwords discovered against Windows with SMB might also be used on Linux or MySQL or custom Web
applications. Discovering a password greatly beneficial for a pen-tester.

This script uses a lot of little tricks that I (Ron Bowes) describe in detail in a blog posting (see references).
The tricks will be summarized here, but that blog is the best place to learn more.

Usernames and passwords are initially taken from the unpwdb library. If possible, the usernames are
verified as existing by taking advantage of Windows' odd behaviour with invalid username and invalid
password responses. As soon as it is able, this script will download a full list  of usernames from
actual accounts only.

SYNTAX:

userdb:  The filename of an alternate username database.

brutelimit:  Limits the number of usernames checked in the script. In some domains,
it's possible to end up with 10.000+ usernames on each server. By default, this
will be '5000', which should be higher than most servers and also prevent infinite
loops or other weird things. This will only affect the user list pulled from the
server, not the username list.

randomseed:    Set to a value to change the filenames/service names that are randomly generated.

unpwdb.timelimit:  The maximum amount of time that any iterator will run
before stopping. The value is in seconds by default and you can follow it
with 'ms', 's', 'm', or 'h' for
milliseconds, seconds, minutes, or hours. For example,
'unpwdb.timelimit=30m' or 'unpwdb.timelimit=.5h' for
30 minutes. The default depends on the timing template level (see the module
description). Use the value '0' to disable the time limit.

unpwdb.userlimit:  The maximum number of usernames
'usernames' will return (default unlimited).

smblockout:  This argument will force the script to continue if it
locks out an account or thinks it will lock out an account.

smbport:       Override the default port choice. If 'smbport' is open, it's used. It's assumed
to be the same protocol as port 445, not port 139. Since it probably isn't possible to change
Windows' ports normally, this is mostly useful if you're bouncing through a relay or something.

passdb:  The filename of an alternate password database.

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

canaries:  Sets the number of tests to do to attempt to lock out the first account.
This will lock out the first account without locking out the rest of the accounts.
The default is 3, which will only trigger strict lockouts, but will also bump the
canary account up far enough to detect a lockout well before other accounts are
hit.

unpwdb.passlimit:  The maximum number of passwords
'passwords' will return (default unlimited)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

