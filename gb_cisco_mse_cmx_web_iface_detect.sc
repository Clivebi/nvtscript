if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105461" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-20 12:46:40 +0100 (Fri, 20 Nov 2015)" );
	script_name( "Cisco Mobility Service Engine Web Interface Detection" );
	script_tag( name: "summary", value: "This script performs HTTP(s) based detection of Cisco Mobility Service Engine" );
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
port = http_get_port( default: 443 );
url = "/api/config/v1/version/image";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "cmx_image_version" ) && ContainsString( buf, "cmx_rpm_versions" )){
	version = eregmatch( pattern: "cisco_cmx_wips-([^\"]+)", string: buf );
	if(!isnull( version[1] )){
		set_kb_item( name: "cisco_mse/http/version", value: version[1] );
		set_kb_item( name: "cisco_mse/lsc", value: TRUE );
		report = "Cisco Mobility Service Engine Web Interface is running at this port\nVersion: " + version[1] + "\nCPE: cpe:/a:cisco:mobility_services_engine:" + version[1];
		log_message( port: port, data: report );
		exit( 0 );
	}
}
url = "/mseui/";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "<title>Sign in - Cisco MSE</title>" )){
	report = "Cisco Mobility Service Engine Web Interface is running at this port\nCPE: cpe:/a:cisco:mobility_services_engine";
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

