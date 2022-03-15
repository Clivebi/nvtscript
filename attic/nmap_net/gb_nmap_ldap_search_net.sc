if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104149" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: ldap-search" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to perform an LDAP search and returns all matches.

If no username and password is supplied to the script the Nmap registry is consulted. If the <code
>ldap-brute' script has been selected and it found a valid account, this account will be used.
If not anonymous bind will be used as a last attempt.

SYNTAX:

ldap.base:  If set, the script will use it as a base for the search. By default the defaultNamingContext is retrieved and used.
If no defaultNamingContext is available the script iterates over the available namingContexts


ldap.username:  If set, the script will attempt to perform an LDAP bind using the username and password


ldap.password:  If set, used together with the username to authenticate to the LDAP server


ldap.qfilter:  If set, specifies a quick filter. The library does not support parsing real LDAP filters.
The following values are valid for the filter parameter: computer, users or all. If no value is specified it defaults to all.


ldap.attrib:  If set, the search will include only the attributes specified. For a single attribute a string value can be used, if
multiple attributes need to be supplied a table should be used instead.


ldap.maxobjects:  If set, overrides the number of objects returned by the script (default 20).
The value -1 removes the limit completely." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

