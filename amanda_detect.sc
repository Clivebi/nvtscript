if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10462" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Amanda client version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Paul J. Ewing Jr." );
	script_family( "Service detection" );
	script_require_udp_ports( 10080, 10081 );
	script_tag( name: "summary", value: "This detects the Amanda backup system client
  version. The client version gives potential attackers additional
  information about the system they are attacking." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
func get_amanda_version( soc, port, timeout ){
	var result, temp, version, data;
	if( !isnull( timeout ) ) {
		result = recv( socket: soc, length: 2048, timeout: timeout );
	}
	else {
		result = recv( socket: soc, length: 2048 );
	}
	if(result){
		if(egrep( pattern: "^[^ ]+ [0-9]+\\.[0-9]+", string: result )){
			temp = strstr( result, " " );
			temp = temp - " ";
			temp = strstr( temp, " " );
			version = result - temp;
			data = NASLString( "Amanda version: ", version );
			log_message( port: port, data: data, protocol: "udp" );
			service_register( port: port, ipproto: "udp", proto: "amanda" );
			set_kb_item( name: "Amanda/running", value: TRUE );
		}
	}
}
req = "Amanda 2.3 REQ HANDLE 000-65637373 SEQ 954568800\nSERVICE " + rand_str( length: 8 ) + "\n";
port1 = 10080;
if(get_udp_port_state( port1 )){
	soc1 = open_sock_udp( port1 );
	if(soc1){
		send( socket: soc1, data: req );
		get_amanda_version( soc: soc1, port: port1, timeout: NULL );
		close( soc1 );
	}
}
port2 = 10081;
if(get_udp_port_state( port2 )){
	soc2 = open_sock_udp( port2 );
	if(soc2){
		send( socket: soc2, data: req );
		get_amanda_version( soc: soc2, port: port2, timeout: 1 );
		close( soc2 );
	}
}
exit( 0 );

