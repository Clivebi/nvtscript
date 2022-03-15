if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104022" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_cve_id( "CVE-2006-5835" );
	script_bugtraq_id( 20960 );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: domino-enum-users" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?rs=463&uid=swg21248026" );
	script_tag( name: "summary", value: "Attempts to discover valid IBM Lotus Domino users and download their ID files by exploiting the
CVE-2006-5835 vulnerability.

SYNTAX:

userdb:  The filename of an alternate username database.

domino-id.username:  the name of the user from which to retrieve the ID.
If this parameter is not specified, the unpwdb library will be used to
brute force names of users.

For more information see the references.

Credits

  - ------
o Ollie Whitehouse for bringing this to my attention back in the days when
it was first discovered and for the c-code on which this is based.

passdb:  The filename of an alternate password database.

unpwdb.passlimit:  The maximum number of passwords
'passwords' will return (default unlimited).

domino-id.path:  the location to which any retrieved ID files are stored

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

