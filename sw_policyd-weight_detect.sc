if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111037" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-09-12 10:00:00 +0200 (Sat, 12 Sep 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "poliycd-weight Server Detection" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_dependencies( "find_service_3digits.sc" );
	script_require_ports( "Services/unknown", 12525 );
	script_tag( name: "summary", value: "The script checks the presence of a policyd-weight server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 12525 );
host = get_host_name();
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = "helo_name=" + host + "\r\n" + "sender=openvas@" + host + "\r\n" + "client_address=" + get_host_ip() + "\r\n" + "request=smtpd_access_policy" + "\r\n\r\n";
send( socket: soc, data: req );
buf = recv( socket: soc, length: 256 );
close( soc );
if(concluded = egrep( string: buf, pattern: "action=(ACTION|DUNNO|550|450|PREPEND)(.*)" )){
	install = port + "/tcp";
	service_register( port: port, proto: "policyd-weight" );
	set_kb_item( name: "policyd-weight/installed", value: TRUE );
	cpe = "cpe:/a:policyd-weight:policyd-weight";
	register_product( cpe: cpe, location: install, port: port );
	log_message( data: build_detection_report( app: "policyd-weight server", install: install, cpe: cpe, concluded: concluded ), port: port );
}
exit( 0 );

