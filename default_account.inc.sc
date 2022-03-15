func recv_until( socket, pattern ){
	var socket, pattern;
	var i, r, buf;
	i = 0;
	for(;TRUE;){
		i++;
		if(i > 65535){
			return NULL;
		}
		r = recv( socket: socket, length: 1 );
		if(strlen( r ) == 0){
			return NULL;
		}
		buf += r;
		if(egrep( pattern: pattern, string: buf )){
			return buf;
		}
	}
}
func _check_telnet( port, login, password ){
	var port, login, password;
	var soc, res;
	soc = open_sock_tcp( port );
	if(!soc){
		return ( 0 );
	}
	res = telnet_init( soc );
	res += recv_until( socket: soc, pattern: "ogin:" );
	if(!res){
		exit( 0 );
	}
	send( socket: soc, data: login + "\r\n" );
	if(isnull( password )){
		send( socket: soc, data: "id\r\n" );
		res = recv_until( socket: soc, pattern: "uid=" );
		close( soc );
		if( res ) {
			return 1;
		}
		else {
			return 0;
		}
	}
	res = recv_until( socket: soc, pattern: "word:" );
	if(isnull( res )){
		close( soc );
		return 0;
	}
	send( socket: soc, data: password + "\r\n" );
	send( socket: soc, data: "id\r\n" );
	res = recv_until( socket: soc, pattern: "uid=" );
	close( soc );
	if( res ) {
		return 1;
	}
	else {
		return 0;
	}
}
func check_account( login, password ){
	var login, password;
	var port, ret, soc, res;
	if(!login){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#login#-#check_account" );
	}
	ports = ssh_get_ports( default_port_list: make_list( 22 ) );
	for port in ports {
		if(!ssh_broken_random_login( port: port )){
			soc = open_sock_tcp( port );
			if(soc){
				ret = ssh_login( socket: soc, login: login, password: password, priv: NULL, passphrase: NULL );
				close( soc );
				if(ret == 0){
					return port;
				}
			}
		}
	}
	port = telnet_get_port( default: 23 );
	if(get_kb_item( "telnet/" + port + "/no_login_banner" )){
		return;
	}
	if(isnull( password )){
		password = "";
	}
	res = _check_telnet( port: port, login: login, password: password );
	if( res ) {
		return port;
	}
	else {
		return;
	}
}

