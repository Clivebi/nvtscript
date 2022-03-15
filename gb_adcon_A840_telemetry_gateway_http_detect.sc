if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105489" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-12-17 16:12:43 +0100 (Thu, 17 Dec 2015)" );
	script_name( "Adcon A840 Telemetry Gateway Detection (HTTP)" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
if(!buf || !ContainsString( buf, "Welcome to the A840 Telemetry Gateway" )){
	exit( 0 );
}
set_kb_item( name: "tg_A840/installed", value: TRUE );
set_kb_item( name: "tg_A840/http/port", value: port );
version = eregmatch( pattern: ">Release ([0-9.]+[^,]+),", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "tg_A840/http/version", value: vers );
}
report = "Detected Adcon Telemetry Gateway A840.\n";
if(vers){
	report += "Version: " + vers + "\n";
}
log_message( port: port, data: report );
exit( 0 );

