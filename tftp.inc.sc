func tftp_get( port, path ){
	var port, path;
	var source_port, destination_port, request_data, request_ip, request_udp, filter, response_udp, response_data;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#tftp_get" );
		return NULL;
	}
	if(!path){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#path#-#tftp_get" );
		return NULL;
	}
	source_port = 23793 + int( ( rand() % 6157 ) );
	destination_port = port;
	request_data = raw_string( 0x00, 0x01 ) + path + raw_string( 0x00 ) + "octet" + raw_string( 0x00 );
	request_ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20, ip_id: rand(), ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP, ip_src: this_host() );
	request_udp = forge_udp_packet( ip: request_ip, uh_sport: source_port, uh_dport: destination_port, uh_ulen: 8 + strlen( request_data ), data: request_data );
	filter = "udp and dst port " + source_port + " and src host " + get_host_ip();
	response_udp = send_packet( packet: request_udp, pcap_active: TRUE, pcap_filter: filter );
	if(response_udp){
		response_data = get_udp_element( udp: response_udp, element: "data" );
		if(strlen( response_data ) > 3 && ord( response_data[0] ) == 0x00 && ord( response_data[1] ) == 0x03 && ord( response_data[2] ) == 0x00 && ord( response_data[3] ) == 0x01){
			response_data = substr( response_data, 4 );
			return ( response_data );
		}
	}
	return NULL;
}
func tftp_put( port, path ){
	var port, path;
	var source_port, destination_port, request_data, request_ip, request_udp, filter, response_udp, response_data;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#tftp_put" );
	}
	if(!path){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#path#-#tftp_put" );
	}
	source_port = 32288 + int( ( rand() % 7354 ) );
	destination_port = port;
	request_data = raw_string( 0x00, 0x02 ) + path + raw_string( 0x00 ) + "octet" + raw_string( 0x00 );
	request_ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20, ip_id: rand(), ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP, ip_src: this_host() );
	request_udp = forge_udp_packet( ip: request_ip, uh_sport: source_port, uh_dport: destination_port, uh_ulen: 8 + strlen( request_data ), data: request_data );
	filter = "udp and dst port " + source_port + " and src host " + get_host_ip();
	response_udp = send_packet( packet: request_udp, pcap_active: TRUE, pcap_filter: filter );
	if(response_udp){
		response_data = get_udp_element( udp: response_udp, element: "data" );
		if(strlen( response_data ) > 3 && ord( response_data[0] ) == 0x00 && ord( response_data[1] ) == 0x04 && ord( response_data[2] ) == 0x00 && ord( response_data[3] ) == 0x00){
			return ( TRUE );
		}
	}
	return NULL;
}
func tftp_alive( port ){
	var port;
	var vt_strings, req, sport, ip, u, filter, data, i, rep;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#tftp_alive" );
		return NULL;
	}
	vt_strings = get_vt_strings();
	req = "\x00\x01" + vt_strings["default_rand"] + "\0netascii\0";
	sport = rand() % 64512 + 1024;
	ip = forge_ip_packet( ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20, ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP, ip_src: this_host() );
	u = forge_udp_packet( ip: ip, uh_sport: sport, uh_dport: port, uh_ulen: 8 + strlen( req ), data: req );
	filter = "udp and dst port " + sport + " and src host " + get_host_ip() + " and udp[8:1]=0x00";
	data = NULL;
	for(i = 0;i < 2;i++){
		rep = send_packet( packet: u, pcap_active: TRUE, pcap_filter: filter );
		if(rep){
			data = get_udp_element( udp: rep, element: "data" );
			if(data[0] == "\0" && ( data[1] == "\x03" || data[1] == "\x05" )){
				return TRUE;
			}
		}
	}
}
func tftp_has_reliable_get( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#tftp_has_reliable_get" );
		return NULL;
	}
	if(get_kb_item( "tftp/" + port + "/backdoor" )){
		return FALSE;
	}
	if(get_kb_item( "tftp/" + port + "/rand_file_response" )){
		return FALSE;
	}
	return TRUE;
}

