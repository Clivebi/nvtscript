if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140498" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-11-13 10:14:34 +0700 (Mon, 13 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ProConOS Detection" );
	script_tag( name: "summary", value: "A ProConOS Service is running at this host.

ProConOS is a high performance PLC run time engine designed for both embedded and PC based control applications." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 20547 );
	script_xref( name: "URL", value: "https://www.plantautomation.com/doc/proconos-0001" );
	exit( 0 );
}
require("host_details.inc.sc");
require("dump.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = 20547;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
query = raw_string( 0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x00, 0x47, 0xee );
send( socket: soc, data: query );
recv = recv( socket: soc, length: 1024 );
close( soc );
if(hexstr( substr( recv, 0, 1 ) ) != "cc01"){
	exit( 0 );
}
llr = bin2string( ddata: substr( recv, 12, 43 ), noprint_replacement: "" );
set_kb_item( name: "proconos/llr", value: llr );
type = bin2string( ddata: substr( recv, 44, 75 ), noprint_replacement: "" );
set_kb_item( name: "proconos/type", value: type );
prj_name = bin2string( ddata: substr( recv, 76, 87 ), noprint_replacement: "" );
boot_prj = bin2string( ddata: substr( recv, 88, 99 ), noprint_replacement: "" );
src = bin2string( ddata: substr( recv, 100, 105 ), noprint_replacement: "" );
set_kb_item( name: "proconos/detected", value: TRUE );
service_register( port: port, proto: "proconos" );
report = "A ProConOS service is running at this port.\n\nThe following information was extracted:\n\n" + "Ladder Logic Runtime:  " + llr + "\n" + "PLC Type:              " + type + "\n" + "Project Name:          " + prj_name + "\n" + "Boot Project:          " + boot_prj + "\n" + "Project Source Code:   " + src + "\n";
log_message( port: port, data: report );
exit( 0 );

