if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107366" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-12 16:31:12 +0100 (Mon, 12 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ServersCheck Monitoring Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "ServersCheck_Monitoring_Server/banner" );
	script_tag( name: "summary", value: "Detection of ServersCheck Monitoring Server using HTTP." );
	script_xref( name: "URL", value: "https://serverscheck.com/monitoring-software/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !IsMatchRegexp( banner, "Server: ServersCheck_Monitoring_Server" )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "serverscheck/monitoring_server/http/detected", value: TRUE );
set_kb_item( name: "serverscheck/monitoring_software_or_server/detected", value: TRUE );
set_kb_item( name: "serverscheck/monitoring_server/http/port", value: port );
vers = eregmatch( pattern: "ServersCheck_Monitoring_Server/([0-9.]+)", string: banner, icase: TRUE );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "serverscheck/monitoring_server/http/version", value: version );
	set_kb_item( name: "serverscheck/monitoring_server/http/concluded", value: vers[0] );
}
register_and_report_cpe( app: "ServersCheck Monitoring Server", ver: version, base: "cpe:/a:serverscheck:monitoring_server:", expr: "^([0-9.]+)", insloc: "/", regPort: port, concluded: vers[0], regService: "www" );
exit( 0 );

