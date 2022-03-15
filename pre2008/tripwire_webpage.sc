if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10743" );
	script_version( "2021-02-26T10:28:36+0000" );
	script_tag( name: "last_modification", value: "2021-02-26 10:28:36 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Tripwire for Webpages Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "tripwire/banner" );
	script_xref( name: "URL", value: "http://www.securiteam.com/securitynews/5RP0L1540K.html" );
	script_tag( name: "summary", value: "We detected the remote web server is running Tripwire
  for Webpages under the Apache HTTP Server." );
	script_tag( name: "impact", value: "This software allows attackers to gather sensitive
  information about the server configuration." );
	script_tag( name: "solution", value: "Modify the banner used by Apache HTTP Server by
  adding the option 'ServerTokens' to 'ProductOnly' in httpd.conf." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( string: banner, pattern: "^Server\\s*:\\s*Apache.* Intrusion/", icase: TRUE )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

