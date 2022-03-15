if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140215" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-06-19 06:17:59 +0000 (Wed, 19 Jun 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Network Data Management Protocol (NDMP) Detection" );
	script_tag( name: "summary", value: "A NDMP Service is running at this host.

  NDMP is used primarily for backup of network-attached storage (NAS) devices, such as storage systems." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 10000 );
	script_xref( name: "URL", value: "https://www.snia.org/ndmp" );
	exit( 0 );
}
require("byte_func.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
if(!port = unknownservice_get_port( default: 10000 )){
	exit( 0 );
}
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
recv = recv( socket: soc, length: 4 );
if(!recv || !IsMatchRegexp( hexstr( recv ), "^800000" )){
	close( soc );
	exit( 0 );
}
len = getdword( blob: recv, pos: 0 ) & 0x7fffffff;
if(len < 24 || len > 100){
	close( soc );
	exit( 0 );
}
hexbanner = recv;
recv = recv( socket: soc, length: len );
if(!recv || strlen( recv ) != len){
	close( soc );
	exit( 0 );
}
hexbanner += recv;
close( soc );
if(hexstr( substr( recv, 0, 3 ) ) != "00000001"){
	exit( 0 );
}
service_register( port: port, ipproto: "tcp", proto: "ndmp" );
set_kb_item( name: "ndmp/" + port + "/hex_banner", value: hexstr( hexbanner ) );
report = "A Network Data Management Protocol (NDMP) service is running on this port.";
log_message( data: report, port: port );
exit( 0 );

