if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105840" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-01 09:56:19 +0200 (Mon, 01 Aug 2016)" );
	script_name( "Cisco Prime Infrastructure Health Monitor Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8082 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8082 );
buf = http_get_cache( port: port, item: "/login.jsp" );
if(!ContainsString( buf, "Cisco Prime Infrastructure" ) || !ContainsString( buf, "Health Monitor Login Page" )){
	exit( 0 );
}
set_kb_item( name: "ciscp_prime_infrastructure/health_monitor/installed", value: TRUE );
set_kb_item( name: "ciscp_prime_infrastructure/health_monitor/port", value: port );
version = eregmatch( pattern: "productVersion\">[\r\n]*\\s*Version: ([0-9.]+)", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "ciscp_prime_infrastructure/health_monitor/version", value: vers );
}
report = "Cisco Prime Infrastructure Health Monitor Login Page is running at this port.";
if(vers){
	report += "\nVersion: " + vers + "\nCPE: cpe:/a:cisco:prime_infrastructure\n";
}
log_message( port: port, data: report );
exit( 0 );

