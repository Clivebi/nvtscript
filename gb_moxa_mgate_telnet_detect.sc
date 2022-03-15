if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105822" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-25 13:26:43 +0200 (Mon, 25 Jul 2016)" );
	script_name( "Moxa MGate Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/moxa/mgate/detected" );
	script_tag( name: "summary", value: "This script performs Telnet based detection of Moxa MGate" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
banner = bin2string( ddata: banner, noprint_replacement: " " );
if(!banner || !IsMatchRegexp( banner, "Model name\\s*:\\s*MGate " )){
	exit( 0 );
}
version = "unknown";
build = "unknown";
model = "unknown";
vb = eregmatch( pattern: "Firmware version\\s*:\\s*([0-9.]+) Build ([0-9]+[^ \r\n])", string: banner );
if(!isnull( vb[1] )){
	version = vb[1];
}
if(!isnull( vb[2] )){
	build = vb[2];
}
mod = eregmatch( pattern: "Model name\\s*:\\s*MGate ([^ \r\n]+)", string: banner );
if(!isnull( mod[1] )){
	model = mod[1];
}
set_kb_item( name: "moxa/mgate/detected", value: TRUE );
set_kb_item( name: "moxa/mgate/telnet/port", value: port );
set_kb_item( name: "moxa/mgate/telnet/" + port + "/concluded", value: banner );
set_kb_item( name: "moxa/mgate/telnet/" + port + "/model", value: model );
set_kb_item( name: "moxa/mgate/telnet/" + port + "/version", value: version );
set_kb_item( name: "moxa/mgate/telnet/" + port + "/build", value: build );
exit( 0 );

