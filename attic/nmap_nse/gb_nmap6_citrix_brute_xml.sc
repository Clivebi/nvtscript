if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803539" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:28 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: citrix-brute-xml" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Attempts to guess valid credentials for the Citrix PN Web Agent XML Service. The XML service
authenticates against the local Windows server or the Active Directory.

This script makes no attempt of preventing account lockout. If the password list contains more
passwords than the lockout-threshold accounts will be locked.

SYNTAX:

userdb:  The filename of an alternate username database.

unpwdb.passlimit:  The maximum number of passwords
'passwords' will return (default unlimited).

passdb:  The filename of an alternate password database.

unpwdb.userlimit:  The maximum number of usernames
'usernames' will return (default unlimited).

unpwdb.timelimit:  The maximum amount of time that any iterator will run
before stopping. The value is in seconds by default and you can follow it
with 'ms', 's', 'm', or 'h' for
milliseconds, seconds, minutes, or hours. For example,
'unpwdb.timelimit=30m' or 'unpwdb.timelimit=.5h' for
30 minutes. The default depends on the timing template level (see the module
description). Use the value '0' to disable the time limit." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

