var _ftp_func_debug;
_ftp_func_debug = FALSE;
var _ftp_is_broken_array, __ftp_kb_login, __ftp_kb_pass;
_ftp_is_broken_array = make_array();
func ftp_open_socket( port ){
	var port;
	var soc, banner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ftp_open_socket" );
		return NULL;
	}
	if(ftp_get_is_marked_broken( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return NULL;
	}
	banner = ftp_recv_line( socket: soc );
	if(!ftp_verify_banner( data: banner )){
		close( soc );
		return NULL;
	}
	return soc;
}
func ftp_close( socket ){
	var socket;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ftp_close" );
		return;
	}
	send( socket: socket, data: "QUIT\r\n" );
	close( socket );
}
func ftp_get_banner( port ){
	var port;
	var banner, soc, csid_cmd, csid_banner, help_cmd, help_banner, syst_cmd, syst_banner;
	var stat_cmd, stat_banner, creds, user, pass, quit_cmd, quit_banner;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ftp_get_banner" );
		return FALSE;
	}
	banner = get_kb_item( "FTP/banner/" + port );
	if(banner){
		return ( banner );
	}
	if(!get_port_state( port )){
		return NULL;
	}
	if(ftp_get_is_marked_broken( port: port )){
		return NULL;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		ftp_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = ftp_recv_line( socket: soc, retry: 1 );
	if(!ftp_verify_banner( data: banner )){
		close( soc );
		ftp_set_is_marked_broken( port: port );
		return NULL;
	}
	banner = chomp( banner );
	csid_cmd = "CSID Name=OpenVAS; Version=" + OPENVAS_VERSION + ";";
	csid_banner = ftp_get_cmd_banner( port: port, socket: soc, cmd: csid_cmd );
	if(csid_banner){
		set_kb_item( name: "ftp/fingerprints/" + port + "/csid_banner_noauth", value: csid_banner );
	}
	if(egrep( pattern: "^200 .+", string: csid_banner )){
		banner += "\n" + csid_banner;
	}
	help_cmd = "HELP";
	help_banner = ftp_get_cmd_banner( port: port, socket: soc, cmd: help_cmd );
	if(help_banner){
		set_kb_item( name: "ftp/fingerprints/" + port + "/help_banner_noauth", value: help_banner );
	}
	syst_cmd = "SYST";
	syst_banner = ftp_get_cmd_banner( port: port, socket: soc, cmd: syst_cmd );
	if(syst_banner){
		set_kb_item( name: "ftp/fingerprints/" + port + "/syst_banner_noauth", value: syst_banner );
	}
	stat_cmd = "STAT";
	stat_banner = ftp_get_cmd_banner( port: port, socket: soc, cmd: stat_cmd );
	if(stat_banner){
		set_kb_item( name: "ftp/fingerprints/" + port + "/stat_banner_noauth", value: stat_banner );
	}
	if(egrep( pattern: "^530 .+", string: csid_banner ) || egrep( pattern: "^530 .+", string: help_banner ) || egrep( pattern: "^530 .+", string: syst_banner ) || egrep( pattern: "^530 .+", string: stat_banner )){
		creds = ftp_get_kb_creds();
		user = creds["login"];
		pass = creds["pass"];
		if(ftp_authenticate( socket: soc, user: user, pass: pass, skip_banner: TRUE )){
			csid_banner = ftp_send_cmd( socket: soc, cmd: csid_cmd );
			csid_banner = chomp( csid_banner );
			if(egrep( pattern: "^200 .+", string: csid_banner )){
				banner += "\n" + csid_banner;
				replace_kb_item( name: "ftp/cmd/" + csid_cmd + "_banner/" + port, value: csid_banner );
			}
			if(csid_banner){
				set_kb_item( name: "ftp/fingerprints/" + port + "/csid_banner_authed", value: csid_banner );
			}
			help_banner = ftp_send_cmd( socket: soc, cmd: help_cmd );
			help_banner = chomp( help_banner );
			if(egrep( pattern: "^214 .+", string: help_banner )){
				replace_kb_item( name: "ftp/cmd/" + help_cmd + "_banner/" + port, value: help_banner );
			}
			if(help_banner){
				set_kb_item( name: "ftp/fingerprints/" + port + "/help_banner_authed", value: help_banner );
			}
			syst_banner = ftp_send_cmd( socket: soc, cmd: syst_cmd );
			syst_banner = chomp( syst_banner );
			if(egrep( pattern: "^215 .+", string: syst_banner )){
				replace_kb_item( name: "ftp/cmd/" + syst_cmd + "_banner/" + port, value: syst_banner );
			}
			if(syst_banner){
				set_kb_item( name: "ftp/fingerprints/" + port + "/syst_banner_authed", value: syst_banner );
			}
			stat_banner = ftp_send_cmd( socket: soc, cmd: stat_cmd );
			stat_banner = chomp( stat_banner );
			if(egrep( pattern: "^211 .+", string: stat_banner )){
				replace_kb_item( name: "ftp/cmd/" + stat_cmd + "_banner/" + port, value: stat_banner );
			}
			if(stat_banner){
				set_kb_item( name: "ftp/fingerprints/" + port + "/stat_banner_authed", value: stat_banner );
			}
		}
	}
	replace_kb_item( name: "FTP/banner/" + port, value: banner );
	quit_cmd = "QUIT";
	quit_banner = ftp_get_cmd_banner( port: port, socket: soc, cmd: quit_cmd );
	if(quit_banner){
		set_kb_item( name: "ftp/fingerprints/" + port + "/quit_banner", value: quit_banner );
	}
	close( soc );
	return banner;
}
func ftp_get_cmd_banner( port, socket, cmd, retry, return_errors ){
	var port, socket, cmd, retry, return_errors;
	var banner, socket_no_close;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ftp_get_cmd_banner" );
		return FALSE;
	}
	if(!cmd){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cmd#-#ftp_get_cmd_banner" );
		return FALSE;
	}
	banner = get_kb_item( "ftp/cmd/" + cmd + "_banner/" + port );
	if(banner){
		return ( banner );
	}
	if(!get_port_state( port )){
		return NULL;
	}
	if(ftp_get_is_marked_broken( port: port )){
		return NULL;
	}
	if( !socket ){
		socket = open_sock_tcp( port );
		if(!socket){
			ftp_set_is_marked_broken( port: port );
			return NULL;
		}
		banner = ftp_recv_line( socket: socket, retry: retry );
		if(!ftp_verify_banner( data: banner )){
			close( socket );
			if( return_errors ) {
				return banner;
			}
			else {
				return NULL;
			}
		}
	}
	else {
		socket_no_close = TRUE;
	}
	banner = ftp_send_cmd( socket: socket, cmd: cmd, retry: retry );
	if(!socket_no_close){
		ftp_close( socket: socket );
	}
	if(!ftp_verify_banner( data: banner )){
		if( return_errors ) {
			return banner;
		}
		else {
			return NULL;
		}
	}
	banner = chomp( banner );
	replace_kb_item( name: "ftp/cmd/" + cmd + "_banner/" + port, value: banner );
	return banner;
}
func ftp_send_cmd( socket, cmd, retry ){
	var socket, cmd, retry;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ftp_send_cmd" );
		return;
	}
	if(!cmd){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cmd#-#ftp_send_cmd" );
		return;
	}
	send( socket: socket, data: cmd + "\r\n" );
	return ftp_recv_line( socket: socket, retry: retry );
}
func ftp_recv_line( socket, retry ){
	var n, r, res, t1, t2, socket, retry;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ftp_recv_line" );
		return;
	}
	r = recv_line( socket: socket, length: 65535 );
	n = 0;
	if(_ftp_func_debug){
		t1 = unixtime();
	}
	for(;strlen( r ) == 0 && n++ < retry;){
		r = recv_line( socket: socket, length: 65535 );
	}
	if(_ftp_func_debug){
		t2 = unixtime();
		if(n > 0 && t2 - t1 > 1){
			display( "ftp_recv_line: retried ", n, " time( s ) = ", t2 - t1, "s. Increase read timeout!\n" );
		}
	}
	if(strlen( r ) < 4){
		return r;
	}
	n = 0;
	res = r;
	for(;( strlen( r ) > 3 && r[3] == "-" ) || ( strlen( r ) >= 3 && r[0] == " " );){
		n++;
		r = recv_line( socket: socket, length: 65535 );
		if(n > 255){
			return;
		}
		res += r;
	}
	return res;
}
func ftp_recv_listing( socket ){
	var n, r, buf, socket;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ftp_recv_listing" );
		return;
	}
	n = 0;
	r = recv_line( socket: socket, length: 65535 );
	buf = r;
	for(;strlen( r );){
		n++;
		if(n > 4096){
			return;
		}
		r = recv_line( socket: socket, length: 65535 );
		buf += r;
	}
	return buf;
}
func ftp_recv_data( socket, line ){
	var buf, bytes, min, socket, line;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ftp_recv_data" );
		return;
	}
	if(line != NULL){
		bytes = ereg_replace( pattern: "^150.*\\(([0-9]*) .*\\)", string: line, replace: "\\1" );
	}
	if( !bytes ){
		bytes = 8192;
		min = 1;
	}
	else {
		min = int( bytes );
		bytes = int( bytes );
	}
	return recv( socket: socket, min: bytes, length: bytes );
}
func ftp_authenticate( socket, user, pass, skip_banner ){
	var socket, user, pass, skip_banner;
	var oid, r;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ftp_authenticate" );
		return NULL;
	}
	if(!user){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.14707"){
			set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#user#-#ftp_authenticate" );
		}
	}
	if(!pass){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.11160"){
			set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#pass#-#ftp_authenticate" );
		}
	}
	if(!skip_banner){
		r = ftp_recv_line( socket: socket );
	}
	send( socket: socket, data: "USER " + user + "\r\n" );
	r = ftp_recv_line( socket: socket );
	if(r[0] != "3" && r[0] != "2"){
		return FALSE;
	}
	send( socket: socket, data: "PASS " + pass + "\r\n" );
	r = ftp_recv_line( socket: socket );
	if( r[0] != "2" ){
		return FALSE;
	}
	else {
		return TRUE;
	}
}
func ftp_pasv( socket ){
	var r, port, array, socket;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ftp_pasv" );
		return;
	}
	send( socket: socket, data: "PASV\r\n" );
	r = ftp_recv_line( socket: socket );
	if(r[0] != "2"){
		return FALSE;
	}
	port = egrep( pattern: "^227 .* \\([0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+\\)", string: r );
	if(!port){
		return FALSE;
	}
	array = eregmatch( pattern: "^227 .* \\([0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9]+),([0-9]+)\\)", string: port );
	if(isnull( array )){
		return FALSE;
	}
	port = int( array[1] ) * 256 + int( array[2] );
	return port;
}
func ftp_get_port( default, nodefault, ignore_broken, ignore_unscanned ){
	var default, nodefault, ignore_broken, ignore_unscanned;
	var port;
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#ftp_get_port" );
		exit( 0 );
	}
	port = get_kb_item( "Services/ftp" );
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
	if(!ignore_broken && ftp_get_is_marked_broken( port: default )){
		exit( 0 );
	}
	return default;
}
func ftp_get_ports( default_port_list, ignore_broken, ignore_unscanned ){
	var default_port_list, ignore_broken, ignore_unscanned;
	var final_port_list, check_port_list, default_ports, num_ports, ports, _port;
	final_port_list = make_list();
	check_port_list = make_list();
	default_ports = make_list( 21,
		 990 );
	num_ports = 0;
	ports = get_kb_list( "Services/ftp" );
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
		if(!ignore_broken && ftp_get_is_marked_broken( port: _port )){
			continue;
		}
		final_port_list = make_list( final_port_list,
			 _port );
	}
	return final_port_list;
}
func ftp_get_kb_creds( default_login, default_pass ){
	var default_login, default_pass;
	var login, pass, ret_array;
	if( !isnull( __ftp_kb_login ) && !default_login ){
		login = NASLString( __ftp_kb_login );
	}
	else {
		login = get_kb_item( "ftp/login" );
		if(isnull( login )){
			if( default_login ) {
				login = default_login;
			}
			else {
				login = "anonymous";
			}
		}
		if(!default_login){
			__ftp_kb_login = NASLString( login );
		}
	}
	if( !isnull( __ftp_kb_pass ) && !default_pass ){
		pass = NASLString( __ftp_kb_pass );
	}
	else {
		pass = get_kb_item( "ftp/password" );
		if(isnull( pass )){
			if( default_pass ) {
				pass = default_pass;
			}
			else {
				pass = "anonymous@example.com";
			}
		}
		if(!default_pass){
			__ftp_kb_pass = NASLString( pass );
		}
	}
	ret_array["login"] = login;
	ret_array["pass"] = pass;
	return ret_array;
}
func ftp_get_is_marked_broken( port ){
	var port;
	var marked_broken_list, marked_broken;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ftp_get_is_marked_broken" );
		return NULL;
	}
	if(!isnull( _ftp_is_broken_array[port] )){
		if( _ftp_is_broken_array[port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	marked_broken = get_kb_item( "ftp/" + port + "/broken" );
	if( marked_broken ){
		_ftp_is_broken_array[port] = TRUE;
	}
	else {
		_ftp_is_broken_array[port] = FALSE;
		marked_broken = FALSE;
	}
	return marked_broken;
}
func ftp_set_is_marked_broken( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ftp_set_is_marked_broken" );
		return NULL;
	}
	set_kb_item( name: "ftp/is_broken", value: TRUE );
	set_kb_item( name: "ftp/" + port + "/broken", value: TRUE );
	_ftp_is_broken_array[port] = TRUE;
	return TRUE;
}
func ftp_verify_banner( data ){
	var data;
	data = chomp( data );
	if(!data){
		return FALSE;
	}
	if(IsMatchRegexp( data, "^[0-9]{3}[ -].+" ) || ContainsString( data, "FTP server ready" ) || ContainsString( data, "FTPd " ) || ContainsString( data, "FTPD" ) || ContainsString( data, "FTP Service" ) || ContainsString( data, "FTP version" ) || ContainsString( data, "FTP service ready" )){
		return TRUE;
	}
	return FALSE;
}
func ftp_broken_random_login( port ){
	var port;
	var count, logins, i, soc, vt_strings, user, pass, login;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ftp_broken_random_login" );
		return NULL;
	}
	if(get_kb_item( "ftp/" + port + "/broken/random_login" )){
		return TRUE;
	}
	if(get_kb_item( "ftp/" + port + "/broken/random_login/checked" )){
		return FALSE;
	}
	count = 0;
	logins = 0;
	for(i = 1;i < 3;i++){
		if(!soc = ftp_open_socket( port: port )){
			sleep( 1 );
			continue;
		}
		vt_strings = get_vt_strings();
		user = vt_strings["lowercase_rand"];
		vt_strings = get_vt_strings();
		pass = vt_strings["default_rand"];
		count++;
		login = ftp_authenticate( socket: soc, user: user, pass: pass, skip_banner: TRUE );
		ftp_close( socket: soc );
		if(login){
			logins++;
		}
		sleep( 1 );
	}
	if(count > 0){
		set_kb_item( name: "ftp/" + port + "/broken/random_login/checked", value: TRUE );
	}
	if(logins > 0){
		set_kb_item( name: "ftp/" + port + "/broken/random_login", value: TRUE );
		return TRUE;
	}
	if( count == 0 ) {
		return NULL;
	}
	else {
		return FALSE;
	}
}

