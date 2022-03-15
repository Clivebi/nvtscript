if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800716" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "MemcacheDB Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_family( "Product detection" );
	script_require_ports( 21201 );
	script_xref( name: "URL", value: "http://memcachedb.org/" );
	script_tag( name: "summary", value: "The script detects the installed version of MemcacheDB and sets
  the result into KB." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
port = 21201;
if(!get_port_state( port )){
	exit( 0 );
}
data = NASLString( "version \\r\\n" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: data );
res = recv( socket: soc, length: 1024 );
close( soc );
if(isnull( res )){
	exit( 0 );
}
version = eregmatch( pattern: "VERSION ([0-9.]+)", string: res );
if(isnull( version[1] )){
	exit( 0 );
}
install = port + "/tcp";
set_kb_item( name: "MemcacheDB/installed", value: TRUE );
set_kb_item( name: "MemcacheDB/version", value: version[1] );
cpe = build_cpe( value: version[1], exp: "^([0-9.]+)", base: "cpe:/a:memcachedb:memcached:" );
if(isnull( cpe )){
	cpe = "cpe:/a:memcachedb:memcached";
}
register_product( cpe: cpe, location: install, port: port );
log_message( data: build_detection_report( app: "MemcacheDB", version: version[1], install: install, cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

