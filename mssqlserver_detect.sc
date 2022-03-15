if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10144" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Microsoft SQL TCP/IP listener is running" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Nicolas Gregoire" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "find_service2.sc" );
	script_require_ports( "Services/unknown", 1433 );
	script_tag( name: "summary", value: "Microsoft SQL server is running on this port." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("mssql.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 1433 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
payload = raw_string( 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00, 0x01, 0xff, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
len = strlen( payload );
req = raw_string( 0x12, 0x01 ) + mkword( len + 8 ) + raw_string( 0x00, 0x00, 0x00, 0x00 ) + payload;
send( socket: soc, data: req );
buf = recv( socket: soc, length: 4096 );
close( soc );
len = strlen( buf );
if(len < 18){
	exit( 0 );
}
res_type = ord( buf[0] );
if(res_type != 4){
	exit( 0 );
}
pos = 8;
if(ord( buf[pos] ) != 0){
	exit( 0 );
}
off = getword( blob: buf, pos: pos + 1 );
blen = getword( blob: buf, pos: pos + 3 );
pos += off;
if(blen < 6 || ( pos + 6 ) > strlen( buf )){
	exit( 0 );
}
version = ord( buf[pos] ) + "." + ord( buf[pos + 1] ) + "." + getword( blob: buf, pos: pos + 2 ) + "." + getword( blob: buf, pos: pos + 4 );
service_register( port: port, proto: "mssql" );
os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port, desc: "Microsoft SQL TCP/IP listener is running", runs_key: "windows" );
set_kb_item( name: "MS/SQLSERVER/Running", value: TRUE );
set_kb_item( name: "OpenDatabase/found", value: TRUE );
releaseName = mssql_get_rel_name( version: version );
install = port + "/tcp";
set_kb_item( name: "MS/SQLSERVER/" + port + "/releasename", value: releaseName );
cpe = "cpe:/a:microsoft:sql_server";
if(releaseName != "unknown release name"){
	cpe_rel = tolower( releaseName );
	cpe_rel = str_replace( string: cpe_rel, find: " ", replace: ":" );
	cpe += "_" + cpe_rel;
}
vers = eregmatch( pattern: "^([0-9.]+)", string: version );
if(!isnull( vers[1] )){
	cpe += ":" + vers[1];
}
register_product( cpe: cpe, location: install, port: port );
log_message( data: build_detection_report( app: "Microsoft SQL Server " + releaseName, version: version, install: install, cpe: cpe ), port: port );
exit( 0 );

