var _pop3_is_broken_array, __pop3_kb_login, __pop3_kb_pass;
_pop3_is_broken_array = make_array();
func pop3_get_banner( port ){
	var port;
	var banner, soc, is_tls, capabanner, n, implbanner, quitbanner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#pop3_get_banner" );
		return FALSE;
	}
	banner = get_kb_item( "POP3/banner/" + port );
	if(banner){
		return banner;
	}
	if(!get_port_state( port )){
		return NULL;
	}
	if(pop3_get_is_marked_broken( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		pop3_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = recv_line( socket: soc, length: 4096 );
	if(!pop3_verify_banner( data: banner )){
		close( soc );
		pop3_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = chomp( banner );
	if( get_port_transport( port ) > ENCAPS_IP ) {
		is_tls = TRUE;
	}
	else {
		is_tls = FALSE;
	}
	send( socket: soc, data: "CAPA\r\n" );
	capabanner = recv_line( socket: soc, length: 4096 );
	capabanner = chomp( capabanner );
	if(capabanner){
		set_kb_item( name: "pop3/fingerprints/" + port + "/capa_banner", value: capabanner );
		if( is_tls ) {
			set_kb_item( name: "pop3/fingerprints/" + port + "/tls_capa_banner", value: capabanner );
		}
		else {
			set_kb_item( name: "pop3/fingerprints/" + port + "/nontls_capa_banner", value: capabanner );
		}
	}
	if(capabanner == "+OK" || ContainsString( tolower( capabanner ), "capability list follows" ) || ContainsString( tolower( capabanner ), "List of capabilities follows" ) || ContainsString( tolower( capabanner ), "capa list follows" ) || ContainsString( capabanner, "list follows" ) || ContainsString( capabanner, "Here's what I can do" )){
		for(;capabanner = recv_line( socket: soc, length: 4096 );){
			n++;
			implbanner = egrep( pattern: "IMPLEMENTATION .*", string: capabanner );
			implbanner = chomp( implbanner );
			if(implbanner){
				set_kb_item( name: "pop3/fingerprints/" + port + "/impl_banner", value: implbanner );
				banner += "\n" + implbanner;
			}
			capabanner = chomp( capabanner );
			if(capabanner && capabanner != "."){
				set_kb_item( name: "pop3/fingerprints/" + port + "/capalist", value: capabanner );
				if( is_tls ) {
					set_kb_item( name: "pop3/fingerprints/" + port + "/tls_capalist", value: capabanner );
				}
				else {
					set_kb_item( name: "pop3/fingerprints/" + port + "/nontls_capalist", value: capabanner );
				}
			}
			if(n > 256){
				break;
			}
		}
	}
	send( socket: soc, data: "QUIT\r\n" );
	quitbanner = recv_line( socket: soc, length: 4096 );
	quitbanner = chomp( quitbanner );
	if(quitbanner){
		set_kb_item( name: "pop3/fingerprints/" + port + "/quit_banner", value: quitbanner );
	}
	close( soc );
	replace_kb_item( name: "POP3/banner/" + port, value: banner );
	return banner;
}
func pop3_get_port( default, nodefault, ignore_broken, ignore_unscanned ){
	var default, nodefault, ignore_broken, ignore_unscanned;
	var port;
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#pop3_get_port" );
		exit( 0 );
	}
	port = get_kb_item( "Services/pop3" );
	if(port){
		default = port;
	}
	if(!default){
		exit( 0 );
	}
	if(!ignore_unscanned && !get_port_state( default )){
		exit( 0 );
	}
	if(port_is_marked_fragile( port: default )){
		exit( 0 );
	}
	if(!ignore_broken && pop3_get_is_marked_broken( port: default )){
		exit( 0 );
	}
	return default;
}
func pop3_get_ports( default_port_list=make_list( 110,
		 995 ), ignore_broken=nil, ignore_unscanned=nil ){
	var default_port_list, ignore_broken, ignore_unscanned;
	var final_port_list, check_port_list, default_ports, num_ports, ports, _port;
	final_port_list = make_list();
	check_port_list = make_list();
	default_ports = make_list( 110,
		 995 );
	num_ports = 0;
	ports = get_kb_list( "Services/pop3" );
	if(ports && NASLTypeof( ports ) == "array"){
		for _port in ports {
			num_ports++;
			check_port_list = make_list( check_port_list,
				 _port );
		}
	}
	if(num_ports == 0){
		if( default_port_list && NASLTypeof( default_port_list ) == "array" ) {
			check_port_list = default_port_list;
		}
		else {
			check_port_list = default_ports;
		}
	}
	for _port in check_port_list {
		if(!ignore_unscanned && !get_port_state( _port )){
			continue;
		}
		if(port_is_marked_fragile( port: _port )){
			continue;
		}
		if(!ignore_broken && pop3_get_is_marked_broken( port: _port )){
			continue;
		}
		final_port_list = make_list( final_port_list,
			 _port );
	}
	return final_port_list;
}
func pop3_open_socket( port ){
	var port;
	var soc, banner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#pop3_open_socket" );
		return NULL;
	}
	if(pop3_get_is_marked_broken( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return NULL;
	}
	banner = recv_line( socket: soc, length: 2048 );
	if(!pop3_verify_banner( data: banner )){
		close( soc );
		return NULL;
	}
	return soc;
}
func pop3_close_socket( socket ){
	var socket;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#pop3_close_socket" );
		return;
	}
	send( socket: socket, data: "QUIT\r\n" );
	recv_line( socket: socket, length: 4096 );
	close( socket );
}
func pop3_get_is_marked_broken( port ){
	var port;
	var marked_broken_list, marked_broken;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#pop3_get_is_marked_broken" );
		return NULL;
	}
	if(!isnull( _pop3_is_broken_array[port] )){
		if( _pop3_is_broken_array[port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	marked_broken = get_kb_item( "pop3/" + port + "/is_broken" );
	if( marked_broken ){
		_pop3_is_broken_array[port] = TRUE;
	}
	else {
		_pop3_is_broken_array[port] = FALSE;
		marked_broken = FALSE;
	}
	return marked_broken;
}
func pop3_set_is_marked_broken( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#pop3_set_is_marked_broken" );
		return NULL;
	}
	set_kb_item( name: "pop3/is_broken", value: TRUE );
	set_kb_item( name: "pop3/" + port + "/is_broken", value: TRUE );
	_pop3_is_broken_array[port] = TRUE;
	return TRUE;
}
func pop3_verify_banner( data ){
	var data;
	data = chomp( data );
	if(!data){
		return FALSE;
	}
	if(eregmatch( pattern: "^\\+OK ", string: data, icase: FALSE ) || ContainsString( data, " POP3" )){
		return TRUE;
	}
	return FALSE;
}
func pop3_get_kb_creds(  ){
	var login, pass, ret_array;
	if( !isnull( __pop3_kb_login ) ){
		login = NASLString( __pop3_kb_login );
	}
	else {
		login = get_kb_item( "pop3/login" );
		if(isnull( login )){
			login = "";
		}
		__pop3_kb_login = NASLString( login );
	}
	if( !isnull( __pop3_kb_pass ) ){
		pass = NASLString( __pop3_kb_pass );
	}
	else {
		pass = get_kb_item( "pop3/password" );
		if(isnull( pass )){
			pass = "";
		}
		__pop3_kb_pass = NASLString( pass );
	}
	ret_array["login"] = login;
	ret_array["pass"] = pass;
	return ret_array;
}

