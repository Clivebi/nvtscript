if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108356" );
	script_version( "2021-04-14T13:21:59+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 13:21:59 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-02-28 09:06:33 +0100 (Wed, 28 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Memcached Detection (UDP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_open_udp_ports.sc" );
	script_require_udp_ports( "Services/udp/unknown", 11211 );
	script_xref( name: "URL", value: "https://www.memcached.org/" );
	script_tag( name: "summary", value: "UDP based detection of Memcached." );
	script_tag( name: "insight", value: "A public available Memcached service with enabled UDP support
  might be misused for Distributed Denial of Service (DDoS) attacks, dubbed 'Memcrashed'. This
  vulnerability is separately checked and reported in the NVT 'Memcached Amplification Attack
  (Memcrashed)' OID: 1.3.6.1.4.1.25623.1.0.108357." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
port = unknownservice_get_port( default: 11211, ipproto: "udp" );
if(!soc = open_sock_udp( port )){
	exit( 0 );
}
req = raw_string( 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 );
data = req + NASLString( "version\\r\\n" );
send( socket: soc, data: data );
res = recv( socket: soc, length: 64 );
close( soc );
if(!res || strlen( res ) < 8){
	exit( 0 );
}
res_str = bin2string( ddata: res, noprint_replacement: " " );
if(!IsMatchRegexp( hexstr( substr( res, 0, 7 ) ), "^([0-9]+)$" ) || !IsMatchRegexp( res_str, "VERSION [0-9.]+" )){
	exit( 0 );
}
version = eregmatch( pattern: "VERSION ([0-9.]+)", string: res_str );
if(isnull( version[1] )){
	exit( 0 );
}
install = port + "/udp";
set_kb_item( name: "memcached/detected", value: TRUE );
set_kb_item( name: "memcached/udp/detected", value: TRUE );
cpe = build_cpe( value: version[1], exp: "^([0-9.]+)", base: "cpe:/a:memcached:memcached:" );
if(!cpe){
	cpe = "cpe:/a:memcached:memcached";
}
register_product( cpe: cpe, location: install, port: port, proto: "udp" );
service_register( port: port, proto: "memcached", ipproto: "udp" );
log_message( data: build_detection_report( app: "Memcached", version: version[1], install: install, cpe: cpe, concluded: version[0] ), port: port, proto: "udp" );
exit( 0 );

