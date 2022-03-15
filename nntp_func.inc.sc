var _nntp_func_debug;
_nntp_func_debug = FALSE;
func nntp_auth( socket, username, password ){
	var socket, username, password;
	var buff;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#nntp_auth" );
		return ( 0 );
	}
	if(!username){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#username#-#nntp_auth" );
		return ( 0 );
	}
	send( socket: socket, data: NASLString( "AUTHINFO USER ", username, "\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	send( socket: socket, data: NASLString( "AUTHINFO PASS ", password, "\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	if(ContainsString( buff, "502 " )){
		if(_nntp_func_debug){
			display( "Bad username/password for NNTP server" );
		}
		return ( 0 );
	}
	return ( 1 );
}
func nntp_connect( port, username, password ){
	var port, username, password;
	var s, buff, a;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#nntp_connect" );
		return ( 0 );
	}
	s = open_sock_tcp( port );
	if(s){
		buff = recv_line( socket: s, length: 2048 );
		a = nntp_auth( socket: s, username: username, password: password );
		if(!a){
			close( s );
			return;
		}
	}
	return ( s );
}
func nntp_post( socket, message ){
	var socket, message;
	var buff;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#nntp_post" );
		return ( 0 );
	}
	send( socket: socket, data: NASLString( "POST\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	if(ContainsString( buff, "340 " )){
		send( socket: socket, data: message );
		buff = recv_line( socket: socket, length: 2048 );
		if(ContainsString( buff, "240 " )){
			return ( 1 );
		}
		if(ereg( pattern: "^4[34][0-9] +.*unwanted distribution .*local", string: buff, icase: TRUE ) && ereg( pattern: "Distribution: +local", string: message )){
			return -1;
		}
	}
	return ( 0 );
}
func nntp_article( id, timeout, port, username, password ){
	var id, timeout, port, username, password;
	var vtstrings, t, s, buff;
	vtstrings = get_vt_strings();
	for(t = 0;t < timeout;t = t + 5){
		sleep( 5 );
		s = nntp_connect( port: port, username: username, password: password );
		if(s){
			send( socket: s, data: NASLString( "ARTICLE ", id, "\\r\\n" ) );
			buff = recv_line( socket: s, length: 2048 );
			send( socket: s, data: NASLString( "QUIT\\r\\n" ) );
			close( s );
			if(ereg( pattern: "^220 .*X-" + vtstrings["default"] + ":", string: buff )){
				return ( buff );
			}
		}
	}
	return ( 0 );
}
func nntp_make_id( str ){
	var str;
	var domain, id;
	domain = get_3rdparty_domain();
	id = NASLString( "<", str, ".x", rand(), "@", domain, ">" );
	return ( id );
}
func nntp_get_port( default ){
	var default;
	var port;
	if(!default){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#nntp_get_port" );
	}
	port = get_kb_item( "Services/nntp" );
	if(port){
		default = port;
	}
	if(port_is_marked_fragile( port: default )){
		exit( 0 );
	}
	if(!get_port_state( default )){
		exit( 0 );
	}
	return default;
}

