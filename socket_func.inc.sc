func close_sock_and_exit( soc ){
	if(soc){
		close( soc );
	}
	exit( 0 );
}
func socket_send_recv( port, soc, data, proto, length ){
	var port, soc, data, proto, length;
	var nosock, recv;
	if(!port && !soc){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port/soc#-#socket_send_recv" );
		return;
	}
	if(proto && proto != "udp" && proto != "tcp"){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#socket_send_recv: proto parameter passed but doesn't contain match 'tcp' or 'udp'" );
		return;
	}
	if(port && soc){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#socket_send_recv: port and soc parameter passed, please chose only one" );
		return;
	}
	if(!soc){
		nosock = TRUE;
	}
	if(port && nosock){
		if(!proto){
			proto = "tcp";
		}
		if( proto == "udp" ){
			if(!get_udp_port_state( port )){
				return;
			}
			soc = open_sock_udp( port );
		}
		else {
			if(!get_tcp_port_state( port )){
				return;
			}
			soc = open_sock_tcp( port );
		}
		if(!soc){
			return;
		}
	}
	if(data){
		send( socket: soc, data: data );
	}
	if(!length){
		length = 1024;
	}
	recv = recv( socket: soc, length: length );
	if(nosock){
		close( soc );
	}
	return chomp( recv );
}

