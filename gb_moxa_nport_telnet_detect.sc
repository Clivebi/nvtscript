if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106588" );
	script_version( "2021-05-19T06:20:42+0000" );
	script_tag( name: "last_modification", value: "2021-05-19 06:20:42 +0000 (Wed, 19 May 2021)" );
	script_tag( name: "creation_date", value: "2017-02-16 09:18:30 +0700 (Thu, 16 Feb 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Moxa NPort Device Detection (Telnet)" );
	script_tag( name: "summary", value: "Telnet based detection of Moxa NPort devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/moxa/nport/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Please keyin your password" ) || IsMatchRegexp( banner, "MiiNePort" ) || IsMatchRegexp( banner, "MGate" )){
	exit( 0 );
}
mod = eregmatch( pattern: "Model name\\s*:\\s(NPort )?([^ \r\n]+)", string: banner );
if(isnull( mod[2] )){
	exit( 0 );
}
version = "unknown";
build = "unknown";
set_kb_item( name: "moxa/nport/detected", value: TRUE );
set_kb_item( name: "moxa/nport/telnet/detected", value: TRUE );
set_kb_item( name: "moxa/nport/telnet/port", value: port );
set_kb_item( name: "moxa/nport/telnet/" + port + "/concluded", value: banner );
set_kb_item( name: "moxa/nport/telnet/" + port + "/model", value: mod[2] );
vers = eregmatch( pattern: "Firmware version\\s*:\\s*([0-9.]+) Build ([0-9]+[^ \r\n])", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
}
if(!isnull( vers[2] )){
	build = vers[2];
}
mac = eregmatch( pattern: "MAC address\\s*:\\s*([^\r\n]+)", string: banner );
if(!isnull( mac[1] )){
	register_host_detail( name: "MAC", value: mac[1], desc: "Moxa NPort Device Detection (Telnet)" );
	replace_kb_item( name: "Host/mac_address", value: mac[1] );
}
set_kb_item( name: "moxa/nport/telnet/" + port + "/version", value: version );
set_kb_item( name: "moxa/nport/telnet/" + port + "/build", value: build );
exit( 0 );

