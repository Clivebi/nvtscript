if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106542" );
	script_version( "2021-09-22T07:55:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-22 07:55:04 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-26 10:19:28 +0700 (Thu, 26 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Schneider Electric Devices Detection (Modbus)" );
	script_tag( name: "summary", value: "Modbus protocol-based detection of Schneider Electric Devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_modbus_detect.sc" );
	script_mandatory_keys( "modbus/vendor", "modbus/prod_code" );
	script_require_ports( "Services/modbus", 502 );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
vendor = get_kb_item( "modbus/vendor" );
if(!vendor || !ContainsString( vendor, "Schneider Electric" )){
	exit( 0 );
}
prod = get_kb_item( "modbus/prod_code" );
if( !prod ) {
	exit( 0 );
}
else {
	set_kb_item( name: "schneider_electric/product", value: prod );
	cpe_prod = tolower( ereg_replace( pattern: " ", string: prod, replace: "" ) );
}
version = "unknown";
vers = get_kb_item( "modbus/version" );
vers = eregmatch( pattern: "(v|V)([0-9.]+)", string: vers );
if(!isnull( vers[2] )){
	version = vers[2];
	set_kb_item( name: "schneider_electric/version", value: version );
}
set_kb_item( name: "schneider_electric/detected", value: TRUE );
port = service_get_port( default: 502, proto: "modbus" );
if(sock = open_sock_tcp( port )){
	req = raw_string( 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x5a, 0x00, 0x02 );
	send( socket: sock, data: req, length: strlen( req ) );
	res = recv( socket: sock, length: 1024, timeout: 1 );
	if(res && strlen( res ) > 33){
		length = ord( res[32] );
		cpu_module = chomp( substr( res, 33, 32 + length ) );
		report = "CPU Module:   " + cpu_module + "\n";
	}
	req = raw_string( 0x01, 0xbf, 0x00, 0x00, 0x00, 0x05, 0x00, 0x5a, 0x00, 0x06, 0x06 );
	send( socket: sock, data: req, length: strlen( req ) );
	res = recv( socket: sock, length: 1024, timeout: 1 );
	if(res && strlen( res ) > 17){
		length = ord( res[16] );
		mem_card = chomp( substr( res, 17, 16 + length ) );
		report += "Memory Card:  " + mem_card + "\n";
	}
	req = raw_string( 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x5a, 0x00, 0x20, 0x00, 0x14, 0x00, 0x64, 0x00, 0x00, 0x00, 0xf6, 0x00 );
	send( socket: sock, data: req, length: strlen( req ) );
	res = recv( socket: sock, length: 1024, timeout: 1 );
	if(res && strlen( res ) > 169){
		proj_info = substr( res, 169 );
		proj_info = bin2string( ddata: proj_info, noprint_replacement: " " );
		report += "Project Info: " + proj_info;
	}
	close( sock );
}
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/h:schneider-electric:" + cpe_prod + ":" );
if(!cpe){
	cpe = "cpe:/h:schneider-electric:" + cpe_prod;
}
install = port + "/tcp";
register_product( cpe: cpe, location: install, port: port, service: "modbus" );
log_message( data: build_detection_report( app: "Schneider Electric " + prod, version: version, install: install, cpe: cpe, concluded: vers[0], extra: report ), port: port );
exit( 0 );

