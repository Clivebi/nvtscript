if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900239" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Checks for open TCP ports" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "dont_scan_printers.sc", "dont_print_on_printers.sc" );
	script_add_preference( name: "Silent", type: "checkbox", value: "yes" );
	script_tag( name: "summary", value: "Collects all open TCP ports identified so far." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
opened_tcp_ports = "";
silent = script_get_preference( "Silent" );
if(silent == "yes"){
	be_silent = TRUE;
}
tcp_ports = get_kb_list( "Ports/tcp/*" );
if(!tcp_ports || !is_array( tcp_ports )){
	if(!be_silent){
		log_message( port: 0, data: "Open TCP ports: [None found]" );
	}
	exit( 0 );
}
keys = sort( keys( tcp_ports ) );
for port in keys {
	_port = eregmatch( string: port, pattern: "Ports/tcp/([0-9]+)" );
	if(!_port && !get_port_state( _port[1] )){
		continue;
	}
	if(!port_is_marked_fragile( port: _port[1] )){
		set_kb_item( name: "TCP/PORTS", value: _port[1] );
	}
	opened_tcp_ports += _port[1] + ", ";
}
if( strlen( opened_tcp_ports ) ){
	opened_tcp_ports = ereg_replace( string: chomp( opened_tcp_ports ), pattern: ",$", replace: "" );
	opened_tcp_ports_kb = str_replace( string: opened_tcp_ports, find: " ", replace: "" );
	set_kb_item( name: "Ports/open/tcp", value: opened_tcp_ports_kb );
	register_host_detail( name: "ports", value: opened_tcp_ports_kb, desc: "Check Open TCP Ports" );
	register_host_detail( name: "tcp_ports", value: opened_tcp_ports_kb, desc: "Check Open TCP Ports" );
	if(be_silent){
		exit( 0 );
	}
	log_message( port: 0, data: "Open TCP ports: " + opened_tcp_ports );
}
else {
	if(!be_silent){
		log_message( port: 0, data: "Open TCP ports: [None found]" );
	}
}
exit( 0 );

