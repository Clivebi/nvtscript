if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803544" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:33 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: http-favicon" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Gets the favicon ('favorites icon')from a web page and matches it against a database of the icons
of known web applications. If there is a match, the name of the application is printed. Otherwise
the MD5 hash of the icon data is printed.

If the script argument 'favicon.uri' is given, that relative URI is always used to find
the favicon. Otherwise, first the page at the root of the web server is retrieved and parsed for a
'<link rel='icon'>' element. If that fails, the icon is looked for in
'/favicon.ico'. If a '<link>' favicon points to a different host or port, it
is ignored.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

favicon.root:  Web server path to search for favicon.

favicon.uri:  URI that will be requested for favicon." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

