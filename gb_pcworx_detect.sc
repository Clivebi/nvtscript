if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140418" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-09-28 15:33:55 +0700 (Thu, 28 Sep 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PCWorx Detection" );
	script_tag( name: "summary", value: "A PCWorx Service is running at this host.

  PCWorx is a protocol and program by Phoenix Contact used by a wide range of industries." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 1962 );
	script_xref( name: "URL", value: "https://www.phoenixcontact.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("dump.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = 1962;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
query = raw_string( 0x01, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x78, 0x80, 0x00, 0x03, 0x00, 0x0c, "IBETH01N0_M", 0x00 );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 512 );
if(hexstr( recv[0] ) != "81" || strlen( recv ) < 20){
	close( soc );
	exit( 0 );
}
sessionid = recv[17];
query = raw_string( 0x01, 0x05, 0x00, 0x16, 0x00, 0x01, 0x00, 0x00, 0x78, 0x80, 0x00, sessionid, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x02, 0x95, 0x00, 0x00 );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 512 );
if(hexstr( recv[0] ) != "81"){
	close( soc );
	exit( 0 );
}
query = raw_string( 0x01, 0x06, 0x00, 0x0e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, sessionid, 0x04, 0x00 );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 512 );
close( soc );
if(hexstr( recv[0] ) != "81"){
	exit( 0 );
}
type = bin2string( ddata: substr( recv, 30, 65 ), noprint_replacement: "" );
set_kb_item( name: "pcworx/plc_type", value: type );
model_num = chomp( bin2string( ddata: substr( recv, 152 ), noprint_replacement: "" ) );
fw_ver = bin2string( ddata: substr( recv, 66, 71 ), noprint_replacement: "" );
set_kb_item( name: "pcworx/fw_version", value: fw_ver );
fw_date = bin2string( ddata: substr( recv, 79, 90 ), noprint_replacement: "" );
fw_time = bin2string( ddata: substr( recv, 91, 99 ), noprint_replacement: "" );
set_kb_item( name: "pcworx/detected", value: TRUE );
service_register( port: port, proto: "pcworx" );
report = "A PCWorx service is running at this port.\\n\\nThe following information was extracted:\\n\\n" + "PLC Type:          " + type + "\\n" + "Model Number:      " + model_num + "\\n" + "Firmware Version:  " + fw_ver + "\\n" + "Firmware Date:     " + fw_date + "\\n" + "Firmware Time:     " + fw_time + "\\n";
log_message( data: report, port: port );
exit( 0 );

