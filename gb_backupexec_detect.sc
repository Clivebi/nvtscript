if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103705" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-04-26 12:18:48 +0200 (Fri, 26 Apr 2013)" );
	script_name( "Symantec/Veritas BackupExec Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 10000 );
	script_tag( name: "summary", value: "Detection of Symantec/Veritas BackupExec.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = 10000;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = recv( socket: soc, length: 4 );
if(isnull( buf )){
	close( soc );
	exit( 0 );
}
len = getword( blob: buf, pos: 2 );
buf = recv( socket: soc, length: len );
if(isnull( buf )){
	close( soc );
	exit( 0 );
}
if(strlen( buf ) < 16 || ord( buf[15] ) != 2 || ord( buf[14] ) != 5){
	close( soc );
	exit( 0 );
}
req = raw_string( 0x80, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 4 );
if(strlen( buf ) < 4){
	close( soc );
	exit( 0 );
}
len = getword( blob: buf, pos: 2 );
buf = recv( socket: soc, length: len );
if(!ContainsString( buf, "VERITAS" )){
	close( soc );
	exit( 0 );
}
req = raw_string( 0x80, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x00, 0x00 );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 4 );
if(strlen( buf ) < 4){
	close( soc );
	exit( 0 );
}
len = getword( blob: buf, pos: 2 );
buf = recv( socket: soc, length: len );
if(strlen( buf ) < 56){
	close( soc );
	exit( 0 );
}
pos = 40;
for(i = 0;i < 4;i++){
	vers += getdword( blob: buf, pos: pos );
	if(i < 3){
		vers += ".";
	}
	pos = pos + 4;
}
close( soc );
set_kb_item( name: "BackupExec/Version", value: vers );
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:symantec:veritas_backup_exec:" );
if(isnull( cpe )){
	cpe = "cpe:/a:symantec:veritas_backup_exec";
}
register_product( cpe: cpe, location: port + "/tcp", port: port );
service_register( port: port, proto: "backupexec", message: "A Symantec/Veritas BackupExec service seems to be running on this port." );
log_message( data: build_detection_report( app: "Symantec/Veritas BackupExec", version: vers, install: port + "/tcp", cpe: cpe, concluded: "Remote probe" ), port: port );
exit( 0 );

