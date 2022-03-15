if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18177" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Websense Reporting Console Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8010 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Filter incoming traffic to this port." );
	script_tag( name: "summary", value: "The remote host appears to be running Websense, connections are allowed
  to the web reporting console." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
CPE = "cpe:/a:websense:enterprise";
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("cpe.inc.sc");
if(os_host_runs( "Windows" ) != "yes"){
	exit( 0 );
}
port = http_get_port( default: 8010 );
url = "/Websense/cgi-bin/WsCgiLogin.exe";
req = http_get( item: url, port: port );
rep = http_keepalive_send_recv( port: port, data: req );
if(!rep){
	exit( 0 );
}
if(ContainsString( rep, "<title>Websense Enterprise - Log On</title>" )){
	http_set_is_marked_embedded( port: port );
	set_kb_item( name: "websense/enterprise/detected", value: TRUE );
	register_and_report_cpe( app: "Websense Enterprise", ver: "unknown", base: CPE, insloc: port + "/tcp", regPort: port, regProto: "tcp" );
}
exit( 0 );

