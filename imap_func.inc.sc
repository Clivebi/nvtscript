var _imap_is_broken_array, __imap_kb_login, __imap_kb_pass;
_imap_is_broken_array = make_array();
func imap_get_banner( port ){
	var port;
	var banner, soc, tag, fpbanner, id, is_tls, capas, _capa;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#imap_get_banner" );
		return FALSE;
	}
	banner = get_kb_item( "IMAP/banner/" + port );
	if(banner){
		return ( banner );
	}
	if(!get_port_state( port )){
		return NULL;
	}
	if(imap_get_is_marked_broken( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		imap_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = recv_line( socket: soc, length: 4096 );
	if(!imap_verify_banner( data: banner )){
		close( soc );
		imap_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = chomp( banner );
	tag = 1;
	send( socket: soc, data: "A0" + tag + " ID (\"name\" \"OpenVAS\" \"version\" \"" + OPENVAS_VERSION + "\" \"vendor\" \"OpenVAS\" \"contact\" \"openvas@example.com\")\r\n" );
	fpbanner = recv( socket: soc, length: 4096 );
	fpbanner = chomp( fpbanner );
	if(ContainsString( fpbanner, "A0" + tag + " BAD" )){
		tag++;
		send( socket: soc, data: "A0" + tag + " ID NIL\r\n" );
		fpbanner = recv( socket: soc, length: 4096 );
		fpbanner = chomp( fpbanner );
	}
	tag++;
	if(fpbanner){
		set_kb_item( name: "imap/fingerprints/" + port + "/id_banner", value: fpbanner );
	}
	id = egrep( string: fpbanner, pattern: "\\* ID .+", icase: TRUE );
	if(id && !ContainsString( id, "ID NIL" )){
		banner += "\n" + chomp( id );
	}
	send( socket: soc, data: "A0" + tag + " CAPABILITY\r\n" );
	fpbanner = recv( socket: soc, length: 4096 );
	fpbanner = chomp( fpbanner );
	tag++;
	if(fpbanner){
		set_kb_item( name: "imap/fingerprints/" + port + "/capa_banner", value: fpbanner );
		if( get_port_transport( port ) > ENCAPS_IP ){
			set_kb_item( name: "imap/fingerprints/" + port + "/tls_capa_banner", value: fpbanner );
			is_tls = TRUE;
		}
		else {
			set_kb_item( name: "imap/fingerprints/" + port + "/nontls_capa_banner", value: fpbanner );
			is_tls = FALSE;
		}
		capas = egrep( string: fpbanner, pattern: "\\* CAPABILITY.+IMAP4rev1", icase: TRUE );
		capas = chomp( capas );
		if(capas){
			capas = split( buffer: capas, sep: " ", keep: FALSE );
			for _capa in capas {
				if(_capa == "*" || _capa == "CAPABILITY" || _capa == "IMAP4rev1"){
					continue;
				}
				set_kb_item( name: "imap/fingerprints/" + port + "/capalist", value: _capa );
				if( is_tls ) {
					set_kb_item( name: "imap/fingerprints/" + port + "/tls_capalist", value: _capa );
				}
				else {
					set_kb_item( name: "imap/fingerprints/" + port + "/nontls_capalist", value: _capa );
				}
			}
		}
	}
	send( socket: soc, data: "A0" + tag + " NOOP\r\n" );
	fpbanner = recv( socket: soc, length: 4096 );
	fpbanner = chomp( fpbanner );
	tag++;
	if(fpbanner){
		set_kb_item( name: "imap/fingerprints/" + port + "/noop_banner", value: fpbanner );
	}
	send( socket: soc, data: "A0" + tag + " UNKNOWNCMD\r\n" );
	fpbanner = recv( socket: soc, length: 4096 );
	fpbanner = chomp( fpbanner );
	tag++;
	if(fpbanner){
		set_kb_item( name: "imap/fingerprints/" + port + "/unknowncmd_banner", value: fpbanner );
	}
	send( socket: soc, data: "A0" + tag + " LOGOUT\r\n" );
	fpbanner = recv( socket: soc, length: 4096 );
	fpbanner = chomp( fpbanner );
	if(fpbanner){
		set_kb_item( name: "imap/fingerprints/" + port + "/logout_banner", value: fpbanner );
	}
	close( soc );
	replace_kb_item( name: "IMAP/banner/" + port, value: banner );
	return banner;
}
func imap_get_port( default, nodefault, ignore_broken, ignore_unscanned ){
	var default, nodefault, ignore_broken, ignore_unscanned;
	var port;
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#imap_get_port" );
		exit( 0 );
	}
	port = get_kb_item( "Services/imap" );
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
	if(!ignore_broken && imap_get_is_marked_broken( port: default )){
		exit( 0 );
	}
	return default;
}
func imap_get_ports( default_port_list= make_list( 143,
		 993 ), ignore_broken=nil, ignore_unscanned=nil ){
	var default_port_list, ignore_broken, ignore_unscanned;
	var final_port_list, check_port_list, default_ports, num_ports, ports, _port;
	final_port_list = make_list();
	check_port_list = make_list();
	default_ports = make_list( 143,
		 993 );
	num_ports = 0;
	ports = get_kb_list( "Services/imap" );
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
		if(!ignore_broken && imap_get_is_marked_broken( port: _port )){
			continue;
		}
		final_port_list = make_list( final_port_list,
			 _port );
	}
	return final_port_list;
}
func imap_open_socket( port ){
	var port;
	var soc, banner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#imap_open_socket" );
		return NULL;
	}
	if(imap_get_is_marked_broken( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return NULL;
	}
	banner = recv_line( socket: soc, length: 4096 );
	if(!imap_verify_banner( data: banner )){
		close( soc );
		return NULL;
	}
	return soc;
}
func imap_close_socket( socket, id ){
	var socket;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#imap_close_socket" );
		return;
	}
	if(!id){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#imap_close_socket" );
		return;
	}
	send( socket: socket, data: id + " LOGOUT\r\n" );
	recv_line( socket: socket, length: 4096 );
	close( socket );
}
func imap_get_is_marked_broken( port ){
	var port;
	var marked_broken_list, marked_broken;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#imap_get_is_marked_broken" );
		return NULL;
	}
	if(!isnull( _imap_is_broken_array[port] )){
		if( _imap_is_broken_array[port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	marked_broken = get_kb_item( "imap/" + port + "/is_broken" );
	if( marked_broken ){
		_imap_is_broken_array[port] = TRUE;
	}
	else {
		_imap_is_broken_array[port] = FALSE;
		marked_broken = FALSE;
	}
	return marked_broken;
}
func imap_set_is_marked_broken( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#imap_set_is_marked_broken" );
		return NULL;
	}
	set_kb_item( name: "imap/is_broken", value: TRUE );
	set_kb_item( name: "imap/" + port + "/is_broken", value: TRUE );
	_imap_is_broken_array[port] = TRUE;
	return TRUE;
}
func imap_verify_banner( data ){
	var data;
	data = chomp( data );
	if(!data){
		return FALSE;
	}
	if(eregmatch( pattern: "^\\* OK", string: data, icase: FALSE ) || ContainsString( data, "IMAP4rev1" )){
		return TRUE;
	}
	return FALSE;
}
func imap_get_kb_creds(  ){
	var login, pass, ret_array;
	if( !isnull( __imap_kb_login ) ){
		login = NASLString( __imap_kb_login );
	}
	else {
		login = get_kb_item( "imap/login" );
		if(isnull( login )){
			login = "";
		}
		__imap_kb_login = NASLString( login );
	}
	if( !isnull( __imap_kb_pass ) ){
		pass = NASLString( __imap_kb_pass );
	}
	else {
		pass = get_kb_item( "imap/password" );
		if(isnull( pass )){
			pass = "";
		}
		__imap_kb_pass = NASLString( pass );
	}
	ret_array["login"] = login;
	ret_array["pass"] = pass;
	return ret_array;
}

