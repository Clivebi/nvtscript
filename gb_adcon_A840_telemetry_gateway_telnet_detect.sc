if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105488" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-12-17 16:01:19 +0100 (Thu, 17 Dec 2015)" );
	script_name( "Adcon A840 Telemetry Gateway Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/adcon/telemetry_gateway_a840/detected" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Telemetry Gateway A840" )){
	exit( 0 );
}
set_kb_item( name: "tg_A840/installed", value: TRUE );
set_kb_item( name: "tg_A840/telnet/port", value: port );
version = eregmatch( pattern: "Telemetry Gateway A840 Version ([0-9.]+[^\r\n ]+)", string: banner );
if(!isnull( version[1] )){
	vers = version[1];
	set_kb_item( name: "tg_A840/telnet/version", value: vers );
}
report = "Detected Adcon Telemetry Gateway A840.\n";
if(vers){
	report += "Version: " + vers + "\n";
}
log_message( port: port, data: report );
exit( 0 );

