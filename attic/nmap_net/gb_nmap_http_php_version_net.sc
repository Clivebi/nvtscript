if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104114" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: http-php-version" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www.0php.com/php_easter_egg.php" );
	script_tag( name: "summary", value: "Attempts to retrieve the PHP version from a web server. PHP has a number of magic queries that
return images or text that can vary with the PHP version. This script uses the following queries:

  * '/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42': gets a GIF logo, which changes on April
Fool's Day.

  * '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000': gets an HTML credits page.

A list of magic queries is available at the references. The script also checks if any
header field value starts with ''PHP'' and reports that value if found.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-max-cache-size:  The maximum memory size (in bytes) of the cache." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

