if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11123" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "radmin detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Malware" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/unknown", 4899 );
	script_tag( name: "solution", value: "Disable it if you do not use it." );
	script_tag( name: "summary", value: "radmin is running on this port.

  Make sure that you use a strong password, otherwise an attacker
  may brute-force it and control your machine.

  If you did not install this on the computer, you may have
  been hacked into. See the references for more information." );
	script_xref( name: "URL", value: "http://www.secnap.com/security/radmin001.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 4899 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = raw_string( 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x08 );
send( socket: soc, data: req );
r = recv( socket: soc, length: 6 );
close( soc );
xp1 = "010000002500";
xp2 = "010000002501";
if(( ContainsString( hexstr( r ), xp1 ) ) || ( ContainsString( hexstr( r ), xp2 ) )){
	log_message( port: port );
	service_register( port: port, proto: "radmin" );
	exit( 0 );
}

