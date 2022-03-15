if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803500" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 18:59:49 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: ftp-brute" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Performs brute force password auditing against FTP servers.

This uses the standard unpwdb username/password list. However, in tests FTP servers are
significantly slower than other servers when responding, so the number of usernames/passwords can be
artificially limited using script arguments.

SYNTAX:

userdb:  The filename of an alternate username database.

unpwdb.timelimit:  The maximum amount of time that any iterator will run
before stopping. The value is in seconds by default and you can follow it
with 'ms', 's', 'm', or 'h' for
milliseconds, seconds, minutes, or hours. For example,
'unpwdb.timelimit=30m' or 'unpwdb.timelimit=.5h' for
30 minutes. The default depends on the timing template level (see the module
description). Use the value '0' to disable the time limit.

unpwdb.userlimit:  The maximum number of usernames
'usernames' will return (default unlimited).

passdb:  The filename of an alternate password database.

passlimit:  The number of passwords to try (default: unlimited).

userlimit:  The number of user accounts to try (default: unlimited).

limit:      Set 'userlimlt' and 'passlimit' at the same time.

unpwdb.passlimit:  The maximum number of passwords
'passwords' will return (default unlimited)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

