var _smtp_is_broken_array, _smtp_is_wrapped_array, __smtp_helo, __3rdparty_domain;
_smtp_is_broken_array = make_array();
_smtp_is_wrapped_array = make_array();
var __smtp_debug;
__smtp_debug = FALSE;
var __smtp_open_helo_ehlo_sent, __smtp_open_helo_ehlo_recv, __smtp_open_banner_recv;
func smtp_close( socket, check_data ){
	var socket, check_data;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#smtp_close" );
		return;
	}
	if(IsMatchRegexp( check_data, "^[0-9]{3}[ -]" ) || check_data == FALSE){
		send( socket: socket, data: "QUIT\r\n" );
		smtp_recv_line( socket: socket );
	}
	close( socket );
}
func smtp_open( port, data, send_helo, send_ehlo, code ){
	var port, data, send_helo, send_ehlo, code;
	var soc, res, req;
	if(!port){
		__smtp_open_helo_ehlo_sent = NULL;
		__smtp_open_helo_ehlo_recv = NULL;
		__smtp_open_banner_recv = NULL;
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_open" );
		return NULL;
	}
	if(send_helo == TRUE && send_ehlo == TRUE){
		__smtp_open_helo_ehlo_sent = NULL;
		__smtp_open_helo_ehlo_recv = NULL;
		__smtp_open_banner_recv = NULL;
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#smtp_open: send_helo and send_ehlo set to TRUE, the function can't decide which one you want to use and will return with NULL" );
		return NULL;
	}
	if(smtp_get_is_marked_broken( port: port )){
		__smtp_open_helo_ehlo_sent = NULL;
		__smtp_open_helo_ehlo_recv = NULL;
		__smtp_open_banner_recv = NULL;
		if(__smtp_debug){
			display( "SMTP DEBUG (smtp_open): SMTP service is marked as broken.\\n" );
		}
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		__smtp_open_helo_ehlo_sent = NULL;
		__smtp_open_helo_ehlo_recv = NULL;
		__smtp_open_banner_recv = NULL;
		if(__smtp_debug){
			display( "SMTP DEBUG (smtp_open): Can't open connection to port ", port, "\\n" );
		}
		return NULL;
	}
	res = smtp_recv_banner( socket: soc );
	if(!res){
		__smtp_open_helo_ehlo_sent = NULL;
		__smtp_open_helo_ehlo_recv = NULL;
		__smtp_open_banner_recv = NULL;
		if(__smtp_debug){
			display( "SMTP DEBUG (smtp_open): No initial 220 banner received from SMTP service.\\n" );
		}
		smtp_close( socket: soc, check_data: res );
		return NULL;
	}
	__smtp_open_banner_recv = str_replace( string: res, find: "\r\n", replace: "<CR><LF>" );
	if(isnull( send_helo ) && !send_ehlo){
		send_helo = TRUE;
	}
	if(isnull( send_helo ) && isnull( send_ehlo )){
		send_helo = TRUE;
		send_ehlo = FALSE;
	}
	if(isnull( data ) || ( send_helo == FALSE && send_ehlo == FALSE )){
		__smtp_open_helo_ehlo_sent = NULL;
		__smtp_open_helo_ehlo_recv = NULL;
		__smtp_open_banner_recv = str_replace( string: res, find: "\r\n", replace: "<CR><LF>" );
		if(__smtp_debug){
			display( "SMTP DEBUG (smtp_open): Successful returning socket without sending a HELO/EHLO first.\\n" );
		}
		return soc;
	}
	if( !send_helo && send_ehlo ) {
		req = strcat( "EHLO ", data, "\r\n" );
	}
	else {
		req = strcat( "HELO ", data, "\r\n" );
	}
	__smtp_open_helo_ehlo_sent = str_replace( string: req, find: "\r\n", replace: "<CR><LF>" );
	if(!code){
		code = "[2-3][0-9]{2}";
	}
	send( socket: soc, data: req );
	res = smtp_recv_line( socket: soc, code: code );
	if(!res){
		__smtp_open_helo_ehlo_recv = NULL;
		if(__smtp_debug){
			display( "SMTP DEBUG (smtp_open): No data received from smtp_recv_line or response didn't matched the regex pattern: ", code, ".\\n" );
		}
		smtp_close( socket: soc, check_data: res );
		return NULL;
	}
	__smtp_open_helo_ehlo_recv = str_replace( string: res, find: "\r\n", replace: "<CR><LF>" );
	if(__smtp_debug){
		display( "SMTP DEBUG (smtp_open): Successful returning socket after sending a HELO/EHLO first.\\n" );
	}
	return soc;
}
func smtp_send_socket( socket, from, to, body ){
	var socket, from, to, body, buff;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#smtp_send_socket" );
	}
	if(!from){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#from#-#smtp_send_socket" );
	}
	if(!to){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#to#-#smtp_send_socket" );
	}
	if(!body){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#body#-#smtp_send_socket" );
	}
	send( socket: socket, data: NASLString( "RSET\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	if(!IsMatchRegexp( from, " *<.*> *" )){
		from = strcat( "<", from, ">" );
	}
	send( socket: socket, data: NASLString( "MAIL FROM: ", from, "\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	if(!ereg( pattern: "^2[0-9][0-9] ", string: buff )){
		return ( 0 );
	}
	if(!IsMatchRegexp( to, " *<.*> *" )){
		to = strcat( "<", to, ">" );
	}
	send( socket: socket, data: NASLString( "RCPT TO: ", to, "\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	if(!ereg( pattern: "^2[0-9][0-9] ", string: buff )){
		return ( 0 );
	}
	send( socket: socket, data: NASLString( "DATA\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	if(!ereg( pattern: "^3[0-9][0-9] ", string: buff )){
		return ( 0 );
	}
	send( socket: socket, data: body );
	send( socket: socket, data: NASLString( "\\r\\n.\\r\\n" ) );
	buff = recv_line( socket: socket, length: 2048 );
	if(!ereg( pattern: "^2[0-9][0-9] ", string: buff )){
		return ( 0 );
	}
	return ( 1 );
}
func smtp_send_port( port, from, to, body ){
	var port, from, to, body;
	var socket, ret;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_send_port" );
		return NULL;
	}
	if(!from){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#from#-#smtp_send_port" );
		return NULL;
	}
	if(!to){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#to#-#smtp_send_port" );
		return NULL;
	}
	if(!body){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#body#-#smtp_send_port" );
		return NULL;
	}
	socket = smtp_open( port: port, data: smtp_get_helo_from_kb( port: port ), send_helo: TRUE, send_ehlo: FALSE );
	if(!socket){
		return NULL;
	}
	ret = smtp_send_socket( socket: socket, from: from, to: to, body: body );
	smtp_close( socket: socket, check_data: ret );
	return ( ret );
}
func smtp_from_header(  ){
	var fromaddr, vt_strings;
	fromaddr = get_kb_item( "SMTP/headers/From" );
	if(!fromaddr){
		vt_strings = get_vt_strings();
		fromaddr = vt_strings["lowercase"] + "@" + get_3rdparty_domain();
	}
	return ( fromaddr );
}
func smtp_to_header(  ){
	var toaddr;
	toaddr = get_kb_item( "SMTP/headers/To" );
	if(!toaddr){
		toaddr = NASLString( "postmaster@[", get_host_ip(), "]" );
	}
	return ( toaddr );
}
func smtp_get_banner( port ){
	var port;
	var banner, soc, ehlo, is_tls, auth_string, auth_lines, _auth_line, help, noop, rset, quit;
	var command_lines, command_line, command, first;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_get_banner" );
		return FALSE;
	}
	banner = get_kb_item( "SMTP/banner/" + port );
	if(banner){
		return ( banner );
	}
	if(!get_port_state( port )){
		return NULL;
	}
	if(smtp_get_is_marked_broken( port: port )){
		return NULL;
	}
	if(smtp_get_is_marked_wrapped( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		smtp_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = smtp_recv_line( socket: soc, retry: 1 );
	if(isnull( banner )){
		close( soc );
		smtp_set_is_marked_wrapped( port: port );
		return NULL;
	}
	if(banner == FALSE || !IsMatchRegexp( banner, "^[0-9]{3}[ -].+" )){
		close( soc );
		smtp_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = chomp( banner );
	replace_kb_item( name: "SMTP/banner/" + port, value: banner );
	send( socket: soc, data: "EHLO " + smtp_get_helo_from_kb( port: port ) + "\r\n" );
	ehlo = smtp_recv_line( socket: soc );
	ehlo = chomp( ehlo );
	if(ehlo){
		set_kb_item( name: "smtp/fingerprints/" + port + "/ehlo_banner", value: ehlo );
		if( get_port_transport( port ) > ENCAPS_IP ){
			is_tls = TRUE;
			set_kb_item( name: "smtp/fingerprints/" + port + "/tls_ehlo_banner", value: ehlo );
		}
		else {
			is_tls = FALSE;
			set_kb_item( name: "smtp/fingerprints/" + port + "/nontls_ehlo_banner", value: ehlo );
		}
		command_lines = split( buffer: ehlo, keep: FALSE );
		first = 0;
		for _command_line in command_lines {
			first++;
			if(first == 1){
				continue;
			}
			command = eregmatch( string: _command_line, pattern: "^250[ -](.+)" );
			if(command[1]){
				set_kb_item( name: "smtp/fingerprints/" + port + "/commandlist", value: command[1] );
				if( is_tls ) {
					set_kb_item( name: "smtp/fingerprints/" + port + "/tls_commandlist", value: command[1] );
				}
				else {
					set_kb_item( name: "smtp/fingerprints/" + port + "/nontls_commandlist", value: command[1] );
				}
			}
		}
		auth_string = egrep( string: ehlo, pattern: "^250[ -]AUTH .+" );
		auth_string = chomp( auth_string );
		if(auth_string){
			set_kb_item( name: "smtp/auth_methods/available", value: TRUE );
			auth_string = substr( auth_string, 9 );
			auth_lines = split( buffer: auth_string, sep: " ", keep: FALSE );
			for _auth_line in auth_lines {
				set_kb_item( name: "smtp/fingerprints/" + port + "/authlist", value: _auth_line );
				if( is_tls ) {
					set_kb_item( name: "smtp/fingerprints/" + port + "/tls_authlist", value: _auth_line );
				}
				else {
					set_kb_item( name: "smtp/fingerprints/" + port + "/nontls_authlist", value: _auth_line );
				}
			}
		}
	}
	send( socket: soc, data: "HELP\r\n" );
	help = smtp_recv_line( socket: soc );
	help = chomp( help );
	if(help){
		set_kb_item( name: "smtp/fingerprints/" + port + "/help_banner", value: help );
	}
	send( socket: soc, data: "NOOP\r\n" );
	noop = smtp_recv_line( socket: soc );
	noop = chomp( noop );
	if(noop){
		set_kb_item( name: "smtp/fingerprints/" + port + "/noop_banner", value: noop );
	}
	send( socket: soc, data: "RSET\r\n" );
	rset = smtp_recv_line( socket: soc );
	rset = chomp( rset );
	if(rset){
		set_kb_item( name: "smtp/fingerprints/" + port + "/rset_banner", value: rset );
	}
	send( socket: soc, data: "QUIT\r\n" );
	quit = smtp_recv_line( socket: soc );
	quit = chomp( quit );
	if(quit){
		set_kb_item( name: "smtp/fingerprints/" + port + "/quit_banner", value: quit );
	}
	close( soc );
	return ( banner );
}
func smtp_recv_line( socket, code, retry, last ){
	var socket, code, retry, last;
	var pat, r, n, ret;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#smtp_recv_line" );
		return NULL;
	}
	if(isnull( retry )){
		retry = 0;
	}
	if(isnull( last )){
		last = FALSE;
	}
	if( isnull( code ) ) {
		pat = "^[0-9]{3}[ -].+";
	}
	else {
		pat = strcat( "^", code, "[ -].+" );
	}
	r = recv_line( socket: socket, length: 4096 );
	n = 0;
	for(;!r && n++ < retry;){
		r = recv_line( socket: socket, length: 4096 );
	}
	if(__smtp_debug && r){
		display( "SMTP DEBUG (smtp_recv_line): Initial response = ", r, "\\n" );
	}
	n = 0;
	ret = r;
	if(strlen( r ) < 4 || !IsMatchRegexp( r, "^[0-9]{3}[ -].+" )){
		return NULL;
	}
	if(!ereg( pattern: pat, string: r )){
		return FALSE;
	}
	for(;ereg( pattern: pat, string: r );){
		n++;
		r = recv_line( socket: socket, length: 4096 );
		if(strlen( r ) == 0){
			break;
		}
		if(n > 512){
			return FALSE;
		}
		if( last ) {
			ret = r;
		}
		else {
			ret = strcat( ret, r );
		}
	}
	if(__smtp_debug && r){
		display( "SMTP DEBUG (smtp_recv_line): Final return = ", ret, "\\n" );
	}
	return ret;
}
func smtp_recv_banner( socket, retry ){
	var socket, retry;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#smtp_recv_banner" );
		return NULL;
	}
	return smtp_recv_line( socket: socket, retry: retry, code: "220" );
}
func smtp_get_port( default, nodefault, ignore_broken, ignore_unscanned ){
	var default, nodefault, ignore_broken, ignore_unscanned;
	var port;
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#smtp_get_port" );
		exit( 0 );
	}
	port = get_kb_item( "Services/smtp" );
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
	if(!ignore_broken && smtp_get_is_marked_broken( port: default )){
		exit( 0 );
	}
	return default;
}
func smtp_get_ports( default_port_list=make_list( 25,
		 465,
		 587 ), ignore_broken=nil, ignore_unscanned=nil ){
	var default_port_list, ignore_broken, ignore_unscanned;
	var final_port_list, check_port_list, default_ports, num_ports, ports, _port;
	final_port_list = make_list();
	check_port_list = make_list();
	default_ports = make_list( 25,
		 465,
		 587 );
	num_ports = 0;
	ports = get_kb_list( "Services/smtp" );
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
		if(!ignore_broken && smtp_get_is_marked_broken( port: _port )){
			continue;
		}
		final_port_list = make_list( final_port_list,
			 _port );
	}
	return final_port_list;
}
func smtp_get_is_marked_broken( port ){
	var port;
	var marked_broken_list, marked_broken;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_get_is_marked_broken" );
		return NULL;
	}
	if(!isnull( _smtp_is_broken_array[port] )){
		if( _smtp_is_broken_array[port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	marked_broken = get_kb_item( "smtp/" + port + "/is_broken" );
	if( marked_broken ){
		_smtp_is_broken_array[port] = TRUE;
	}
	else {
		_smtp_is_broken_array[port] = FALSE;
		marked_broken = FALSE;
	}
	return marked_broken;
}
func smtp_set_is_marked_broken( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_set_is_marked_broken" );
		return NULL;
	}
	set_kb_item( name: "smtp/is_broken", value: TRUE );
	set_kb_item( name: "smtp/" + port + "/is_broken", value: TRUE );
	_smtp_is_broken_array[port] = TRUE;
	return TRUE;
}
func smtp_get_is_marked_wrapped( port ){
	var port;
	var marked_wrapped_list, marked_wrapped;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_get_is_marked_wrapped" );
		return NULL;
	}
	if(!isnull( _smtp_is_wrapped_array[port] )){
		if( _smtp_is_wrapped_array[port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	marked_wrapped = get_kb_item( "smtp/" + port + "/is_wrapped" );
	if( marked_wrapped ){
		_smtp_is_wrapped_array[port] = TRUE;
	}
	else {
		_smtp_is_wrapped_array[port] = FALSE;
		marked_wrapped = FALSE;
	}
	return marked_wrapped;
}
func smtp_set_is_marked_wrapped( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_set_is_marked_wrapped" );
		return NULL;
	}
	set_kb_item( name: "smtp/is_wrapped", value: TRUE );
	set_kb_item( name: "smtp/" + port + "/is_wrapped", value: TRUE );
	_smtp_is_wrapped_array[port] = TRUE;
	return TRUE;
}
func get_3rdparty_domain(  ){
	var domain;
	if( !isnull( __3rdparty_domain ) ){
		domain = NASLString( __3rdparty_domain );
	}
	else {
		domain = get_kb_item( "Settings/third_party_domain" );
		if( !isnull( domain ) ){
			__3rdparty_domain = NASLString( domain );
		}
		else {
			domain = "example.com";
			__3rdparty_domain = domain;
		}
	}
	return domain;
}
func smtp_get_helo_from_kb( port ){
	var port, helo;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#smtp_get_helo_from_kb" );
		return NULL;
	}
	if( !isnull( __smtp_helo ) ){
		helo = NASLString( __smtp_helo );
	}
	else {
		helo = get_kb_item( "smtp/" + port + "/accepted_helo_name" );
		if( !isnull( helo ) ){
			__smtp_helo = NASLString( helo );
		}
		else {
			helo = get_3rdparty_domain();
			__smtp_helo = helo;
		}
	}
	return helo;
}

