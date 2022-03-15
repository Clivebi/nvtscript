if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108018" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-03-22 17:08:49 +0100 (Sun, 22 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DNS Server Detection (TCP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/unknown", 53 );
	script_tag( name: "summary", value: "A DNS Server is running at this Host.
  A Name Server translates domain names into IP addresses. This makes it
  possible for a user to access a website by typing in the domain name instead of
  the website's actual IP address." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("dns_func.inc.sc");
data = raw_string( 0xB8, 0x4C, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x31, 0x01, 0x30, 0x01, 0x30, 0x03, 0x31, 0x32, 0x37, 0x07, 0x69, 0x6E, 0x2D, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0C, 0x00, 0x01 );
data = raw_string( 0x00, 0x28 ) + data;
port = unknownservice_get_port( default: 53 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: data );
buf = recv( socket: soc, length: 4096 );
if(isnull( buf )){
	close( soc );
	exit( 0 );
}
if(strlen( buf ) > 5){
	if(ord( buf[4] ) & 0x80){
		set_kb_item( name: "DNS/tcp/" + port, value: TRUE );
		set_kb_item( name: "DNS/identified", value: TRUE );
		banner = dnsVersionReq( soc: soc, proto: "tcp", port: port );
		if(banner){
			report = "The remote DNS server banner is:\n\n" + banner;
		}
		service_register( port: port, ipproto: "tcp", proto: "domain", message: report );
		log_message( port: port, data: report, protocol: "tcp" );
	}
}
if(soc){
	close( soc );
}
exit( 0 );

