if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141088" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-05-22 14:33:46 +0700 (Tue, 22 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SAP DIAG Service Detection" );
	script_tag( name: "summary", value: "A SAP DIAG (Dynamic Information and Action Gateway) Service is running at
this host.

DIAG is a propretiary communication protocol between the SAP GUI and the SAP application server." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 3200 );
	script_xref( name: "URL", value: "https://www.sap.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("dump.inc.sc");
require("byte_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = unknownservice_get_port( default: 3200 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
init_query = raw_string( 0x00, 0x00, 0x01, 0x06, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x04, 0x02, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x04, 0x4c, 0x00, 0x00, 0x13, 0x89, 0x10, 0x04, 0x0b, 0x00, 0x20, 0xff, 0x7f, 0xfe, 0x2d, 0xda, 0xb7, 0x37, 0xd6, 0x74, 0x08, 0x7e, 0x13, 0x05, 0x97, 0x15, 0x97, 0xef, 0xf2, 0x3f, 0x8d, 0x07, 0x70, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: init_query );
recv = recv( socket: soc, length: 4 );
if(strlen( recv ) != 4){
	close( soc );
	exit( 0 );
}
len = getdword( blob: recv );
recv = recv( socket: soc, length: len );
close( soc );
if(!ContainsString( recv, "UnicodeLittleUnmarked" )){
	exit( 0 );
}
set_kb_item( name: "sap_diag_protocol/detected", value: TRUE );
service_register( port: port, proto: "sap_diag" );
for(i = 0;i < len;i++){
	if(( hexstr( recv[i] ) == "10" ) && ( hexstr( recv[i + 1] ) == "06" ) && ( hexstr( recv[i + 2] ) == "02" )){
		dblen = getword( blob: recv, pos: i + 3 );
		dbname = substr( recv, i + 5, i + 5 + dblen - 1 );
		i += 5 + dblen;
	}
	if(( hexstr( recv[i] ) == "10" ) && ( hexstr( recv[i + 1] ) == "06" ) && ( hexstr( recv[i + 2] ) == "03" )){
		cpulen = getword( blob: recv, pos: i + 3 );
		cpuname = substr( recv, i + 5, i + 5 + cpulen - 1 );
		i += 5 + cpulen;
	}
	if(( hexstr( recv[i] ) == "10" ) && ( hexstr( recv[i + 1] ) == "06" ) && ( hexstr( recv[i + 2] ) == "29" )){
		kernellen = getword( blob: recv, pos: i + 3 );
		kernelver = bin2string( ddata: substr( recv, i + 5, i + 5 + kernellen - 2 ), noprint_replacement: "." );
		i += 5 + kernellen;
	}
	if(( hexstr( recv[i] ) == "10" ) && ( hexstr( recv[i + 1] ) == "06" ) && ( hexstr( recv[i + 2] ) == "06" )){
		diaglen = getword( blob: recv, pos: i + 3 );
		if(diaglen == 2){
			diagver = getword( blob: recv, pos: i + 5 );
		}
		i += 5 + diaglen;
	}
	if(( hexstr( recv[i] ) == "10" ) && ( hexstr( recv[i + 1] ) == "0c" ) && ( hexstr( recv[i + 2] ) == "0a" )){
		icolen = getword( blob: recv, pos: i + 3 );
		sess_icon = substr( recv, i + 5, i + 5 + icolen - 1 );
		i += 5 + icolen;
	}
	if(( hexstr( recv[i] ) == "10" ) && ( hexstr( recv[i + 1] ) == "0c" ) && ( hexstr( recv[i + 2] ) == "09" )){
		titlelen = getword( blob: recv, pos: i + 3 );
		sess_title = substr( recv, i + 5, i + 5 + titlelen - 1 );
		i += 5 + titlelen;
	}
}
report = "A SAP DIAG service is running at this port.";
if(dbname || cpuname){
	report += "\n\nThe following information was extracted:\n\n";
	if(dbname){
		report += "DBNAME:          " + dbname + "\n";
	}
	if(cpuname){
		report += "CPUNAME:         " + cpuname + "\n";
	}
	if(kernelver){
		report += "KERNEL_VERSION:  " + kernelver + "\n";
	}
	if(diagver){
		report += "DIAGVERSION:     " + diagver + "\n";
	}
	if(sess_icon){
		report += "SESSION_ICON:    " + sess_icon + "\n";
	}
	if(sess_title){
		report += "SESSION_TITLE:   " + sess_title + "\n";
	}
}
log_message( port: port, data: report );
exit( 0 );

