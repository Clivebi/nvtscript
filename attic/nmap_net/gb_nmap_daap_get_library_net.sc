if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104130" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: daap-get-library" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www.tapjam.net/daap/" );
	script_tag( name: "summary", value: "Retrieves a list of music from a DAAP server. The list includes artist names and album and song
titles.

Output will be capped to 100 items if not otherwise specified in the 'daap_item_limit'
script argument. A 'daap_item_limit' below zero outputs the complete contents of the DAAP
library.

Based on documentation found in the references.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

daap_item_limit:  Changes the output limit from 100 songs. If set to a negative value, no limit is enforced." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

