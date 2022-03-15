if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11134" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "QMTP Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "find_service2.sc" );
	script_require_ports( "Services/QMTP", 209, 628 );
	script_tag( name: "summary", value: "Checks for the presence of QMTP/QMQP server." );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
ports = service_get_ports( proto: "QMTP", default_port_list: make_list( 209,
	 628 ) );
vt_strings = get_vt_strings();
string_lo = vt_strings["lowercase"];
string_def = vt_strings["default"];
func netstr( str ){
	var l;
	l = strlen( str );
	return strcat( l, ":", str, "," );
}
for port in ports {
	if(!service_is_unknown( port: port )){
		continue;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	msg = strcat( netstr( str: "
Message-ID: <1234567890.666." + string_lo + "@example.org>
From: " + string_lo + "@example.org
To: postmaster@example.com

" + string_def + " is probing this server." ), netstr( str: string_lo + "@example.org" ), netstr( str: netstr( str: "postmaster@example.com" ) ) );
	if( port == 628 ){
		msg = netstr( str: msg );
		srv = "QMQP";
	}
	else {
		srv = "QMTP";
	}
	send( socket: soc, data: msg );
	r = recv( socket: soc, length: 1024 );
	close( soc );
	if(ereg( pattern: "^[1-9][0-9]*:[KZD]", string: r )){
		log_message( port: port );
		service_register( port: port, proto: srv );
	}
}
exit( 0 );

