if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104113" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: smtp-enum-users" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The
goal of this script is to discover all the user accounts in the remote system.

The script will output the list of user names that were found. The script will stop querying the
SMTP server if authentication is enforced. If an error occurs while testing the target host, the
error will be printed with the list of any combinations that were found prior to the error.

The user can specify which methods to use and in which order. The script will ignore repeated
methods. If not specified the script will use the RCPT first, then VRFY and EXPN. An example of how
to specify the methods to use and the order is the following:

'smtp-enum-users.methods={EXPN, RCPT, VRFY}'

SYNTAX:

userdb:  The filename of an alternate username database.

smtp-enum-users.domain:  Define the domain to be used in the SMTP commands

unpwdb.passlimit:  The maximum number of passwords
'passwords' will return (default unlimited).

unpwdb.userlimit:  The maximum number of usernames
'usernames' will return (default unlimited).

unpwdb.timelimit:  The maximum amount of time that any iterator will run
before stopping. The value is in seconds by default and you can follow it
with 'ms', 's', 'm', or 'h' for
milliseconds, seconds, minutes, or hours. For example,
'unpwdb.timelimit=30m' or 'unpwdb.timelimit=.5h' for
30 minutes. The default depends on the timing template level (see the module
description). Use the value '0' to disable the time limit.

smtp-enum-users.methods:  Define the methods and order to be used by the script (EXPN, VRFY, RCPT)

passdb:  The filename of an alternate password database." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

