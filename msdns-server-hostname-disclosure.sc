if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100950" );
	script_version( "2021-03-19T08:40:35+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 08:40:35 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2009-07-10 19:42:14 +0200 (Fri, 10 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Microsoft DNS server internal hostname disclosure detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 Tim Brown" );
	script_dependencies( "dns_server.sc" );
	script_require_udp_ports( "Services/udp/domain", 53 );
	script_mandatory_keys( "DNS/identified" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20140419113733/http://support.microsoft.com:80/kb/198410" );
	script_tag( name: "insight", value: "Microsoft DNS server may disclose the internal hostname of the server in response
  to requests for the hardcoded zones 0.in-addr.arpa and 255.in-addr.arpa." );
	script_tag( name: "solution", value: "On the following platforms, we recommend you resolve in the described manner:

  All default Microsoft DNS server configurations: Please see the referenced KB article KB198410." );
	script_tag( name: "summary", value: "Microsoft DNS server internal hostname disclosure detection" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("port_service_func.inc.sc");
func packet_construct( _dns_zone ){
	_dns_query = raw_string( 0x8d, 0x31, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
	for _dns_node in split( buffer: _dns_zone, sep: ".", keep: FALSE ) {
		_dns_query += raw_string( strlen( _dns_node ) ) + _dns_node;
	}
	_dns_query += raw_string( 0x00, 0x00, 0x06, 0x00, 0x01 );
	return _dns_query;
}
func packet_parse( _dns_query, _dns_response, port ){
	var port;
	if(( _dns_response != "" ) && ( ( ord( _dns_response[3] ) & 2 ) != 2 ) && ( ( ord( _dns_response[3] ) & 3 ) != 3 ) && ( ( ord( _dns_response[3] ) & 5 ) != 5 )){
		_hostdata = substr( _dns_response, 12 + strlen( _dns_query ) + 18 );
		_hostname = "";
		if(strlen( _hostdata ) < 2){
			exit( 0 );
		}
		if(( ord( _hostdata[0] ) != 192 ) && ( ord( _hostdata[1] ) != 12 )){
			_counter1 = 0;
			for(;ord( _hostdata[_counter1] ) != 0;){
				for(_counter2 = 1;_counter2 <= ord( _hostdata[_counter1] );_counter2++){
					_hostname += _hostdata[_counter1 + _counter2];
				}
				_counter1 += _counter2;
				if(ord( _hostdata[_counter1] ) != 0){
					_hostname += ".";
				}
			}
			if(!ContainsString( _hostname, "localhost" )){
				_data = "Microsoft DNS server seems to be running on this port.\n\n" + "Internal hostname disclosed (" + _dns_query + "/SOA/IN): " + _hostname;
				log_message( proto: "udp", port: port, data: _data );
				set_kb_item( name: "DNS/udp/" + port + "/hostname", value: _hostname );
				exit( 0 );
			}
		}
	}
}
port = service_get_port( default: 53, proto: "domain", ipproto: "udp" );
for dns_zone in make_list( "0.in-addr.arpa",
	 "255.in-addr.arpa" ) {
	soc = open_sock_udp( port );
	if(!soc){
		exit( 0 );
	}
	req = packet_construct( _dns_zone: dns_zone );
	send( socket: soc, data: req );
	res = recv( socket: soc, length: 4096 );
	close( soc );
	packet_parse( _dns_query: dns_zone, _dns_response: res, port: port );
}
exit( 99 );

