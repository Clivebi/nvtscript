if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105255" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-14 12:45:24 +0200 (Tue, 14 Apr 2015)" );
	script_name( "Cisco Prime Data Center Network Manager Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/";
install = url;
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>Data Center Network Manager</title>" ) || ( !ContainsString( buf, "productFamily\">Cisco Prime" ) && !ContainsString( buf, "Failed to get information about DCNM" ) )){
	exit( 0 );
}
set_kb_item( name: "cisco_prime_dcnm/installed", value: TRUE );
cpe = "cpe:/a:cisco:prime_data_center_network_manager";
vers = "unknown";
version = eregmatch( pattern: "productVersion\">Version: ([^<]+)<", string: buf );
if( !isnull( version[1] ) ){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "cisco_prime_dcnm/version", value: vers );
}
else {
	url = "/fm/fmrest/about/version";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	version = eregmatch( pattern: "\"version\":\"([^\"]+)", string: res );
	if(!isnull( version[1] )){
		vers = version[1];
		cpe += ":" + vers;
		set_kb_item( name: "cisco_prime_dcnm/version", value: vers );
	}
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "Cisco Prime Data Center Network Manager", version: vers, install: install, cpe: cpe, concluded: version[0], concludedUrl: url ), port: port );
exit( 0 );

