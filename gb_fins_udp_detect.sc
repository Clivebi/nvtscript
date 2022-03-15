if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140538" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-11-24 15:03:31 +0700 (Fri, 24 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Factory Interface Network Service (FINS) Detection (UDP)" );
	script_tag( name: "summary", value: "A Factory Interface Network Service (FINS) over UDP is running at this host.

Factory Interface Network Service, is a network protocol used by Omron PLCs. The FINS communications service was
developed by Omron to provide a consistent way for PLCs and computers on various networks to communicate." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_require_udp_ports( 9600 );
	script_xref( name: "URL", value: "http://www.omron.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("dump.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = 9600;
if(!get_udp_port_state( port )){
	exit( 0 );
}
soc = open_sock_udp( port );
if(!soc){
	exit( 0 );
}
ctrl_data_read = raw_string( 0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x63, 0x00, 0xef, 0x05, 0x01, 0x00 );
send( socket: soc, data: ctrl_data_read );
recv = recv( socket: soc, length: 512 );
close( soc );
if(!recv || ( hexstr( recv[0] ) != "c0" && hexstr( recv[0] ) != "c1" ) || strlen( recv ) < 49){
	exit( 0 );
}
model = bin2string( ddata: substr( recv, 14, 43 ), noprint_replacement: "" );
set_kb_item( name: "fins/model", value: model );
version = bin2string( ddata: substr( recv, 44, 48 ), noprint_replacement: "" );
set_kb_item( name: "fins/version", value: version );
set_kb_item( name: "fins/detected", value: TRUE );
service_register( port: port, proto: "fins", ipproto: "udp" );
report = "A FINS service is running at this port.\\n\\nThe following information was extracted:\\n\\n" + "Controller Model:      " + model + "\\n" + "Controller Version:    " + version + "\\n";
log_message( port: port, data: report, proto: "udp" );
exit( 0 );

