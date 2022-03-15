func udp_ping_pong( port, data, answer ){
	var s, r1, r2;
	if(!port || !get_udp_port_state( port )){
		return 0;
	}
	if( !answer ){
		s = open_sock_udp( port );
		if(!s){
			return 0;
		}
		send( socket: s, data: data );
		r1 = recv( socket: s, length: 1024 );
		close( s );
	}
	else {
		r1 = answer;
	}
	if(!r1){
		return 0;
	}
	s = open_priv_sock_udp( dport: port );
	if(!s){
		return 0;
	}
	send( socket: s, data: data );
	r2 = recv( socket: s, length: 1024 );
	close( s );
	if(!r2){
		return 0;
	}
	return 1;
}

