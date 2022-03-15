if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803554" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:43 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: http-enum" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "http://seclists.org/nmap-dev/2009/q3/0685.html" );
	script_tag( name: "summary", value: "Enumerates directories used by popular web applications and servers.

This parses a fingerprint file that's formatted in a way that's compatible with the Nikto Web
application scanner. This script, however, takes it one step further by building in advanced pattern
matching as well as having the ability to identify specific versions of Web applications.

Currently, the database can be found under Nmap's directory in the nselib/data folder. The file is
called http-fingerprints and has a long description of its functionality in the file header.

Many of the finger prints were discovered by me (Ron Bowes), and a number of them are from the
Yokoso project, used with permission from Kevin Johnson (see references).

Initially, this script attempts to access two different random files in order to detect servers that
don't return a proper 404 Not Found status. In the event that they return 200 OK, the body has any
non-static-looking data removed (URI, time, etc), and saved. If the two random attempts return
different results, the script aborts (since a 200-looking 404 cannot be distinguished from an actual
200). This will prevent most false positives.

In addition, if the root folder returns a 301 Moved Permanently or 401 Authentication Required,
this script will also abort. If the root folder has disappeared or requires authentication, there is
little hope of finding anything inside it.

By default, only pages that return 200 OK or 401 Authentication Required are displayed. If the <code
>http-enum.displayall' script argument is set, however, then all results will be displayed
(except for 404 Not Found and the status code returned by the random files). Entries in the http-
fingerprints database can specify their own criteria for accepting a page as valid.

SYNTAX:

http-enum.basepath:          The base path to prepend to each request. Leading/trailing slashes are ignored.

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-enum.category:          Set to a category (as defined in the fingerprints file). Some options are 'attacks',
'database', 'general', 'microsoft', 'printer', etc.

http-enum.displayall:        Set this argument to display all status codes that may indicate a valid page, not
just 200 OK and 401 Authentication Required pages. Although this is more likely
to find certain hidden folders, it also generates far more false positives.

http-max-cache-size:  The maximum memory size (in bytes) of the cache." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

