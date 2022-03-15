if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104082" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE net: ldap-brute" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to brute-force LDAP authentication. By default it uses the built-in username and password
lists. In order to use your own lists use the 'userdb' and 'passdb' script
arguments.

This script does not make any attempt to prevent account lockout! If the number of passwords in the
dictionary exceed the amount of allowed tries, accounts will be locked out. This usually happens
very quickly.

Authenticating against Active Directory using LDAP does not use the Windows user name but the user
accounts distinguished name. LDAP on Windows 2003 allows authentication using a simple user name
rather than using the fully distinguished name. E.g., 'Patrik Karlsson' vs. 'cn=Patrik
Karlsson, cn=Users, dc=cqure, dc=net' This type of authentication is not supported on e.g. OpenLDAP.

This script uses some AD-specific support and optimizations: * LDAP on Windows 2003 reports
different error messages depending on whether an account exists or not. If the script receives an
error indicating that the username does not exist it simply stops guessing passwords for this
account and moves on to the next. * The script attempts to authenticate with the username only if no
LDAP base is specified. The benefit of authenticating this way is that the LDAP path of each account
does not need to be known in advance as it's looked up by the server.

SYNTAX:

ldap.base:  If set, the script will use it as a base for the password
guessing attempts. If unset the user list must either contain the
distinguished name of each user or the server must support
authentication using a simple user name. See the AD discussion in the description.

passdb:  The filename of an alternate password database.

userdb:  The filename of an alternate username database.

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
description). Use the value '0' to disable the time limit." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

