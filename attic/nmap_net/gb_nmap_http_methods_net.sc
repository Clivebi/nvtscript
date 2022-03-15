if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104075" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: http-methods" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29" );
	script_tag( name: "summary", value: "Finds out what options are supported by an HTTP server by sending an OPTIONS request. Lists
potentially risky methods. Optionally tests each method individually to see if they are subject to
e.g. IP address restrictions.

In this script, 'potentially risky' methods are anything except GET, HEAD, POST, and OPTIONS. If the
script reports potentially risky methods, they may not all be security risks, but you should check
to make sure. This referenced page lists the dangers of some common methods.

The list of supported methods comes from the contents of the Allow and Public header fields. In
verbose mode, a list of all methods is printed, followed by the list of potentially risky methods.
Without verbose mode, only the potentially risky methods are shown.

SYNTAX:

http-methods.url-path:  The path to request. Defaults to
'/'.

http-methods.retest:  If defined, do a request using each method
individually and show the response code. Use of this argument can
make this script unsafe, for example 'DELETE /' is possible.

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored)." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

