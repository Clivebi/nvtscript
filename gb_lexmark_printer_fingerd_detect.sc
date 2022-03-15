if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142839" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-09-03 03:54:10 +0000 (Tue, 03 Sep 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Lexmark Printer Detection (Finger)" );
	script_tag( name: "summary", value: "This script performs a Finger based detection of Lexmark printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/fingerd-printer", 79 );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 79, proto: "fingerd-printer" );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
send( socket: soc, data: raw_string( 0x0d, 0x0a ) );
if(!banner = recv( socket: soc, length: 512, timeout: 5 )){
	close( soc );
	exit( 0 );
}
close( soc );
if(!ContainsString( banner, "Printer Type: Lexmark" )){
	exit( 0 );
}
set_kb_item( name: "lexmark_printer/detected", value: TRUE );
set_kb_item( name: "lexmark_printer/fingerd-printer/detected", value: TRUE );
set_kb_item( name: "lexmark_printer/fingerd-printer/port", value: port );
mod = eregmatch( pattern: "Lexmark ([0-9A-Z]+)", string: banner );
if(!isnull( mod[1] )){
	set_kb_item( name: "lexmark_printer/fingerd-printer/" + port + "/model", value: mod[1] );
	set_kb_item( name: "lexmark_printer/fingerd-printer/" + port + "/concluded", value: mod[0] );
}
exit( 0 );

