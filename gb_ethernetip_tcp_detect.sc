if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106850" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-06-09 12:24:29 +0700 (Fri, 09 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "EtherNet/IP Detection (TCP)" );
	script_tag( name: "summary", value: "A EtherNet/IP Service is running at this host.

  EtherNet/IP is an industrial network protocol that adapts the Common Industrial Protocol to standard Ethernet.
  It is widely used in a range industries including factory, hybrid and process to manage the connection between
  various automation devices such as robots, PLCs, sensors, CNCs and other industrial machines." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 44818 );
	exit( 0 );
}
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("ethernetip.inc.sc");
require("port_service_func.inc.sc");
port = 44818;
if(get_port_state( port )){
	soc = open_sock_tcp( port );
	if(soc){
		ethip_query( proto: "tcp", soc: soc, port: port );
		close( soc );
	}
}
exit( 0 );

