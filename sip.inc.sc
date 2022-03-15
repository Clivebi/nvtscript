func sip_get_banner( port, proto ){
	var port, proto;
	var banner, opt, res, found, _banner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#sip_get_banner" );
		return NULL;
	}
	if(!proto){
		proto = "udp";
	}
	banner = get_kb_item( "sip/banner/" + proto + "/" + port );
	if(banner){
		return banner;
	}
	if( proto == "tcp" ){
		if(!get_tcp_port_state( port )){
			return FALSE;
		}
	}
	else {
		if(!get_udp_port_state( port )){
			return FALSE;
		}
	}
	soc = sip_open_socket( port: port, proto: proto );
	if(!soc){
		return FALSE;
	}
	opt = sip_construct_options_req( port: port, proto: proto );
	send( socket: soc, data: opt );
	res = recv( socket: soc, length: 1024 );
	if(res && sip_verify_banner( data: res )){
		found = TRUE;
	}
	if(!found){
		opt = sip_construct_options_req( port: port, proto: proto, add_branch_rport: TRUE );
		send( socket: soc, data: opt );
		res = recv( socket: soc, length: 1024 );
		if(res && sip_verify_banner( data: res )){
			found = TRUE;
		}
	}
	if(!found){
		send( socket: soc, data: "GET / HTTP/1.0\r\n\r\n" );
		res = recv( socket: soc, length: 1024 );
		if(res && sip_verify_banner( data: res )){
			found = TRUE;
		}
	}
	close( soc );
	if(!found){
		return FALSE;
	}
	replace_kb_item( name: "sip/full_banner/" + proto + "/" + port, value: chomp( res ) );
	if(IsMatchRegexp( res, "Server\\s*:" )){
		_banner = egrep( pattern: "^Server\\s*:\\s*", string: res, icase: TRUE );
		if(_banner){
			_banner = substr( _banner, 8 );
			_banner = chomp( _banner );
		}
		if(_banner){
			set_kb_item( name: "sip/server_banner/" + proto + "/" + port, value: _banner );
			banner = _banner;
		}
	}
	if(IsMatchRegexp( res, "User-Agent\\s*:" )){
		_banner = egrep( pattern: "^User-Agent\\s*:\\s*", string: res, icase: TRUE );
		if(_banner){
			_banner = substr( _banner, 12 );
			_banner = chomp( _banner );
		}
		if(_banner){
			if(banner){
				banner += "\n";
			}
			set_kb_item( name: "sip/useragent_banner/" + proto + "/" + port, value: _banner );
			banner = _banner;
		}
	}
	if(IsMatchRegexp( res, "Allow\\s*:.*OPTIONS.*" )){
		_banner = egrep( pattern: "^Allow\\s*:.*OPTIONS.*", string: res, icase: TRUE );
		if(_banner){
			_banner = substr( _banner, 7 );
			_banner = chomp( _banner );
		}
		if(_banner){
			set_kb_item( name: "sip/options_banner/" + proto + "/" + port, value: _banner );
		}
	}
	if( banner ){
		replace_kb_item( name: "sip/banner/" + proto + "/" + port, value: banner );
		return banner;
	}
	else {
		return FALSE;
	}
}
func sip_send_recv( port, data, proto ){
	var port, data, proto;
	var soc, res;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#sip_send_recv" );
		return NULL;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#sip_send_recv" );
	}
	if(!proto){
		proto = "udp";
	}
	soc = sip_open_socket( port: port, proto: proto );
	if(!soc){
		return FALSE;
	}
	send( socket: soc, data: data );
	res = recv( socket: soc, length: 1024 );
	close( soc );
	res = chomp( res );
	if( res ) {
		return res;
	}
	else {
		return FALSE;
	}
}
func sip_alive( port, proto, retry ){
	var port, proto, retry;
	var i, soc, res, opt;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#sip_alive" );
		return NULL;
	}
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#sip_alive" );
		proto = "udp";
	}
	if(!retry){
		retry = 2;
	}
	i = 0;
	soc = sip_open_socket( port: port, proto: proto );
	for(;!soc && i++ < retry;){
		sleep( 1 );
		soc = sip_open_socket( port: port, proto: proto );
	}
	if(!soc){
		return FALSE;
	}
	opt = sip_construct_options_req( port: port, proto: proto );
	send( socket: soc, data: opt );
	res = recv( socket: soc, length: 1024 );
	close( soc );
	if(!res){
		return FALSE;
	}
	if( ContainsString( res, "SIP/2.0" ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func sip_construct_options_req( port, proto, add_branch_rport ){
	var port, proto, add_branch_rport;
	var vtstrings, ext, opt;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#sip_construct_options_req" );
		port = "5060";
	}
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#sip_construct_options_req" );
		proto = "udp";
	}
	vtstrings = get_vt_strings();
	if(add_branch_rport){
		ext = ";branch=" + vtstrings["lowercase"] + ";rport";
	}
	opt = "OPTIONS sip:" + vtstrings["lowercase"] + "@" + get_host_name() + ":" + port + " SIP/2.0" + "\r\n" + "Via: SIP/2.0/" + toupper( proto ) + " " + this_host() + ":" + port + ext + "\r\n" + "Max-Forwards: 70" + "\r\n" + "To: <sip:" + vtstrings["lowercase"] + "@" + get_host_name() + ":" + port + ">" + "\r\n" + "From: " + vtstrings["default"] + " <sip:" + vtstrings["lowercase"] + "@" + this_host() + ":" + port + ">;tag=" + rand() + "\r\n" + "Call-ID: " + rand() + "\r\n" + "CSeq: 63104 OPTIONS" + "\r\n" + "Contact: <sip:" + vtstrings["lowercase"] + "@" + this_host() + ":" + port + ">" + "\r\n" + "Accept: application/sdp" + "\r\n" + "Content-Length: 0" + "\r\n\r\n";
	return opt;
}
func sip_open_socket( port, proto ){
	var port, proto;
	var soc;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#sip_open_socket" );
		return NULL;
	}
	if(!proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#sip_open_socket" );
		proto = "udp";
	}
	if( proto == "tcp" ){
		if(!get_port_state( port )){
			return FALSE;
		}
		soc = open_sock_tcp( port );
		if(!soc){
			return FALSE;
		}
	}
	else {
		if(!get_udp_port_state( port )){
			return FALSE;
		}
		if( islocalhost() ){
			soc = open_sock_udp( port );
		}
		else {
			soc = open_priv_sock_udp( sport: 5060, dport: port );
		}
		if(!soc){
			return FALSE;
		}
	}
	return soc;
}
func sip_get_port_proto( default_port, default_proto ){
	var default_port, default_proto;
	var port_and_proto, x, x_port, x_proto, ret_arr;
	if(!default_port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default_port#-#sip_get_port_proto" );
		default_port = "5060";
	}
	if(!default_proto){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default_proto#-#sip_get_port_proto" );
		default_proto = "udp";
	}
	port_and_proto = get_kb_item( "sip/port_and_proto" );
	if( port_and_proto ){
		x = split( buffer: port_and_proto, sep: "#-#", keep: FALSE );
		x_port = x[0];
		x_proto = x[1];
	}
	else {
		x_port = default_port;
		x_proto = default_proto;
	}
	if( x_proto == "udp" ){
		if(!get_udp_port_state( x_port )){
			exit( 0 );
		}
	}
	else {
		if(!get_port_state( x_port )){
			exit( 0 );
		}
		if(port_is_marked_fragile( port: x_port )){
			exit( 0 );
		}
	}
	ret_arr["port"] = x_port;
	ret_arr["proto"] = x_proto;
	return ret_arr;
}
func sip_verify_banner( data ){
	var data;
	data = chomp( data );
	if(!data || strlen( data ) < 11){
		return FALSE;
	}
	if(IsMatchRegexp( data, "^SIP/2\\.0 [0-9]{3}" ) && egrep( string: data, pattern: "^(Via|From|To|User-Agent|Allow|Contact):", icase: TRUE )){
		return TRUE;
	}
	return FALSE;
}

