if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108893" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-27 13:32:10 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Chargen Service Detection (TCP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "find_service1.sc", "find_service2.sc" );
	script_require_ports( "Services/chargen", 19 );
	script_tag( name: "summary", value: "TCP based detection of a 'chargen' service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 19, proto: "chargen" );
banner = get_kb_item( "chargen/tcp/" + port + "/banner" );
if(!banner){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	banner = recv_line( socket: soc, length: 1024 );
	close( soc );
}
if(!banner){
	exit( 0 );
}
chargen_found = 0;
for chargen_pattern in make_list( "!\"#$%&\'()*+,-./",
	 "ABCDEFGHIJ",
	 "abcdefg",
	 "0123456789",
	 ":;<=>?@",
	 "KLMNOPQRSTUVWXYZ" ) {
	if(ContainsString( banner, chargen_pattern )){
		chargen_found++;
	}
}
if(chargen_found > 2){
	replace_kb_item( name: "chargen/tcp/" + port + "/banner", value: chomp( banner ) );
	set_kb_item( name: "chargen/tcp/detected", value: TRUE );
	set_kb_item( name: "chargen/tcp/" + port + "/detected", value: TRUE );
	service_register( port: port, proto: "chargen", message: "A chargen service seems to be running on this port." );
	log_message( port: port, data: "A chargen service seems to be running on this port." );
}
exit( 0 );

