if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104126" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE net: sql-injection" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL injection attack.

The script spiders an HTTP server looking for URLs containing queries. It then proceeds to combine
crafted SQL commands with susceptible URLs in order to obtain errors. The errors are analysed to see
if the URL is vulnerable to attack. This uses the most basic form of SQL injection but anything more
complicated is better suited to a standalone tool. Both meta-style and HTTP redirects are supported.

We may not have access to the target web server's true hostname, which can prevent access to
virtually hosted sites.  This script only follows absolute links when the host name component is the
same as the target server's reverse-DNS name.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

sql-injection.start:  The path at which to start spidering, default '/'.

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

sql-injection.maxdepth:  The maximum depth to spider, default 10." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

