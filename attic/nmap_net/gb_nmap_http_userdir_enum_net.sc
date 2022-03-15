if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104039" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_cve_id( "CVE-2001-1013" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Nmap NSE net: http-userdir-enum" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Attempts to enumerate valid usernames on web servers running with the mod_userdir module or similar
enabled.

The Apache mod_userdir module allows user-specific directories to be accessed using the
http://example.com/~user/ syntax.  This script makes http requests in order to discover valid user-
specific directories and infer valid usernames.  By default, the script will use Nmap's
'nselib/data/usernames.lst'.  An HTTP response status of 200 or 403 means the username is
likely a valid one and the username will be output in the script results along with the status code
(in parentheses).

This script makes an attempt to avoid false positives by requesting a directory which is unlikely to
exist.  If the server responds with 200 or 403 then the script will not continue testing it.

SYNTAX:

userdir.users:  The filename of a username list.

limit:  The maximum number of users to check.

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

