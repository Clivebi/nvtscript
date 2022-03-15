func rpc_get_port( program, protocol, portmap ){
	var program, protocol, portmap;
	var a, b, c, d, p_a, p_b, p_c, p_d, pt_a, pt_b, pt_c, pt_d;
	var req, port, broken, len, soc, r;
	if(isnull( program )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#program#-#rpc_get_port" );
		return ( 0 );
	}
	if(isnull( protocol )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#protocol#-#rpc_get_port" );
		return ( 0 );
	}
	a = rand() % 255;
	b = rand() % 255;
	c = rand() % 255;
	d = rand() % 255;
	p_a = program / 16777216;
	p_a = p_a % 256;
	p_b = program / 65356;
	p_b = p_b % 256;
	p_c = program / 256;
	p_c = p_c % 256;
	p_d = program % 256;
	pt_a = protocol / 16777216;
	pt_a = pt_a % 256;
	pt_b = protocol / 65535;
	pt_b = pt_b % 256;
	pt_c = protocol / 256;
	pt_c = pt_c % 256;
	pt_d = protocol % 256;
	req = raw_string( a, b, c, d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, p_a, p_b, p_c, p_d, 0xFF, 0xFF, 0xFF, 0xFF );
	if( protocol == IPPROTO_TCP ) {
		req += raw_string( 0x00, 0x00, 0x00, 0x06 );
	}
	else {
		req += raw_string( pt_a, pt_b, pt_c, pt_d );
	}
	req += raw_string( 0x00, 0x00, 0x00, 0x00 );
	if(protocol == IPPROTO_TCP){
		req = mkdword( strlen( req ) ) + req;
		req = raw_string( 0x80 | ord( req[0] ) ) + substr( req, 1, strlen( req ) );
	}
	if( isnull( portmap ) ){
		port = int( get_kb_item( "rpc/portmap" ) );
		if(port == 0){
			port = 111;
		}
	}
	else {
		port = portmap;
	}
	broken = get_kb_item( "/tmp/rpc/noportmap/" + port );
	if(broken){
		return ( 0 );
	}
	if( protocol == IPPROTO_TCP ){
		len = 32;
		soc = open_sock_tcp( port );
	}
	else {
		len = 28;
		soc = open_sock_udp( port );
	}
	if(!soc){
		return;
	}
	send( socket: soc, data: req );
	r = recv( socket: soc, length: len );
	close( soc );
	if(!r){
		set_kb_item( name: "/tmp/rpc/noportmap/" + port, value: TRUE );
		return ( 0 );
	}
	if( strlen( r ) != len ){
		return ( 0 );
	}
	else {
		port = getdword( blob: raw_string( r[len - 4], r[len - 3], r[len - 2], r[len - 1] ) );
		if( protocol == IPPROTO_TCP ){
			if( get_tcp_port_state( port ) ){
				return ( port );
			}
			else {
				return ( 0 );
			}
		}
		else {
			if( get_udp_port_state( port ) ){
				return ( port );
			}
			else {
				return ( 0 );
			}
		}
	}
}
func rpc_construct_packet( program, prog_ver, procedure, data, udp, credentials, verifier ){
	var program, prog_ver, procedure, data, udp, credentials, verifier;
	var xid, header, cred_data, verifier_data, rpc_packet, data_len, frag_header;
	if(isnull( program )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#program#-#rpc_construct_packet" );
	}
	if(isnull( prog_ver )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#prog_ver#-#rpc_construct_packet" );
	}
	if(isnull( procedure )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#procedure#-#rpc_construct_packet" );
	}
	if(isnull( credentials )){
		credentials[0] = 0;
		credentials[1] = 0;
	}
	if(isnull( verifier )){
		verifier[0] = 0;
		verifier[1] = 0;
	}
	xid = rand();
	header = mkdword( xid );
	header += mkdword( 0 );
	header += mkdword( 2 );
	header += mkdword( program );
	header += mkdword( prog_ver );
	header += mkdword( procedure );
	cred_data = mkdword( credentials[0] );
	cred_data += mkdword( strlen( credentials[1] ) );
	verifier_data = mkdword( verifier[0] );
	verifier_data += mkdword( strlen( verifier[1] ) );
	rpc_packet = header + cred_data + verifier_data + data;
	if(udp != "udp" || udp == FALSE){
		data_len = strlen( header + cred_data + verifier_data + data );
		frag_header = mkbyte( 0x80 );
		frag_header += mkbyte( 0 );
		frag_header += mkdword( data_len );
		rpc_packet = frag_header + rpc_packet;
	}
	return ( rpc_packet );
}

