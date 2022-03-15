if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143177" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 04:42:17 +0000 (Tue, 26 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache ZooKeeper Detection" );
	script_tag( name: "summary", value: "Detection of Apache ZooKeeper.

  The script sends a connection request to the server and attempts to detect Apache ZooKeeper and extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 2181 );
	script_xref( name: "URL", value: "https://zookeeper.apache.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 2181 );
sock = open_sock_tcp( port );
if(!sock){
	exit( 0 );
}
send( socket: sock, data: "stat" );
recv = recv( socket: sock, length: 2048 );
close( sock );
if(!ContainsString( recv, "Zookeeper version" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "Zookeeper version: ([0-9.]+)", string: recv );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "apache/zookeeper/detected", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:zookeeper:" );
if(!cpe){
	cpe = "cpe:/a:apache:zookeeper";
}
service_register( port: port, ipproto: "tcp", proto: "zookeeper" );
register_product( cpe: cpe, location: "/", port: port, service: "zookeeper" );
extra = "\nFull server response:\n\n" + recv;
log_message( data: build_detection_report( app: "Apache ZooKeeper", version: version, install: "/", cpe: cpe, concluded: vers[0], extra: extra ), port: port );
exit( 0 );

