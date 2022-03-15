var _ssh_banner;
var _ssh_error;
var _last_libssh_sess;
var ssh_host_key_algos, ssh_expired_pw_text;
var __ssh_elevate_privs_enabled_nd_working, __ssh_kb_privlogin, __ssh_kb_privpassword;
ssh_host_key_algos = make_list( "ssh-rsa",
	 "ssh-dss",
	 "ecdsa-sha2-nistp256",
	 "ecdsa-sha2-nistp384",
	 "ecdsa-sha2-nistp521",
	 "ssh-ed25519",
	 "rsa-sha2-256",
	 "rsa-sha2-512" );
ssh_expired_pw_text = make_list( "You are required to change your password immediately",
	 "WARNING: Your password has expired.",
	 "You must change your password now and login again!",
	 "(current) UNIX password:",
	 "Enter new UNIX password:",
	 "Password change requested. Choose a new password.",
	 "Old Password:",
	 "Enter existing login password:" );
func kb_ssh_login(  ){
	return NASLString( get_kb_item( "Secret/SSH/login" ) );
}
func kb_ssh_password(  ){
	return NASLString( get_kb_item( "Secret/SSH/password" ) );
}
func kb_ssh_privatekey(  ){
	return NASLString( get_kb_item( "Secret/SSH/privatekey" ) );
}
func kb_ssh_publickey(  ){
	return NASLString( get_kb_item( "Secret/SSH/publickey" ) );
}
func kb_ssh_passphrase(  ){
	return NASLString( get_kb_item( "Secret/SSH/passphrase" ) );
}
func kb_ssh_transport(  ){
	var r;
	r = get_preference( "auth_port_ssh" );
	if(r){
		return int( r );
	}
	r = get_kb_item( "Services/ssh" );
	if( r ) {
		return int( r );
	}
	else {
		return 22;
	}
}
func ssh_kb_privlogin(  ){
	var login;
	if( !isnull( __ssh_kb_privlogin ) ){
		login = NASLString( __ssh_kb_privlogin );
	}
	else {
		login = NASLString( get_kb_item( "Secret/SSH/privlogin" ) );
		__ssh_kb_privlogin = login;
	}
	return login;
}
func ssh_kb_privpassword(  ){
	var password;
	if( !isnull( __ssh_kb_privpassword ) ){
		password = NASLString( __ssh_kb_privpassword );
	}
	else {
		password = NASLString( get_kb_item( "Secret/SSH/privpassword" ) );
		__ssh_kb_privpassword = password;
	}
	return password;
}
func ssh_get_server_host_key( sess_id ){
	if(isnull( sess_id )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#sess_id#-#get_server_host_key" );
		return NULL;
	}
	if(sess_id && int( sess_id ) > 0){
		_last_libssh_sess = sess_id;
	}
	return ssh_get_host_key( _last_libssh_sess );
}
func ssh_set_error( msg ){
	var msg;
	_ssh_error = msg;
}
func ssh_get_error(  ){
	return _ssh_error;
}
func ssh_get_supported_authentication( sess_id ){
	var sess_id;
	if(isnull( sess_id )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#sess_id#-#ssh_get_supported_authentication" );
		return NULL;
	}
	if(sess_id && int( sess_id ) > 0){
		_last_libssh_sess = sess_id;
	}
	return ssh_get_auth_methods( _last_libssh_sess );
}
func init(  ){
	_ssh_banner = "";
	_ssh_error = "";
	_last_libssh_sess = 0;
}
func ssh_recv( socket, length ){
	var socket, length;
	var header, len, trailer, ret;
	header = recv( socket: socket, length: 4, min: 4 );
	if(strlen( header ) < 4){
		return ( NULL );
	}
	len = ntol( buffer: header, begin: 0 );
	if(( len == 0 ) || ( len > 32768 )){
		return ( header );
	}
	trailer = recv( socket: socket, length: len, min: len );
	if(strlen( trailer ) < len){
		return ( NULL );
	}
	ret = ord( trailer[1] );
	if(( ret == 2 ) || ( ret == 53 )){
		if(ret == 53){
			_ssh_banner += getstring( buffer: trailer, pos: 2 );
		}
		return ssh_recv( socket: socket, length: length );
	}
	return strcat( header, trailer );
}
func ssh_exchange_identification( socket ){
	var socket;
	var buf, sshversion, num, vt_strings, prot;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ssh_exchange_identification" );
		return;
	}
	buf = recv_line( socket: socket, length: 1024 );
	if(!buf){
		ssh_set_error( msg: "The scanner did not receive the server's version." );
		return 0;
	}
	if(!ssh_verify_server_ident( data: buf )){
		ssh_set_error( msg: "Remote service is not a valid SSH service." );
		return 0;
	}
	sshversion = split( buffer: buf, sep: "-", keep: FALSE );
	num = split( buffer: sshversion[1], sep: ".", keep: FALSE );
	if(( num[0] != 2 ) && !( ( num[0] == 1 ) && ( num[1] == 99 ) )){
		ssh_set_error( msg: "The scanner only supports SSHv2." );
		return 0;
	}
	vt_strings = get_vt_strings();
	prot = "SSH-2.0-" + vt_strings["default"] + raw_string( 0x0a );
	send( socket: socket, data: prot );
	if( ContainsString( buf, "\r\n" ) ) {
		buf = buf - "\r\n";
	}
	else {
		buf = buf - "\n";
	}
	return buf;
}
func getstring( buffer, pos ){
	var buffer, pos;
	var buf_len, buf;
	buf_len = ntol( buffer: buffer, begin: pos );
	buf = substr( buffer, pos + 4, pos + 4 + buf_len - 1 );
	return buf;
}
func ssh_login( socket, login, password, priv, passphrase, keytype ){
	var socket, login, password, priv, passphrase, keytype;
	var oid, sess, auth_successful;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ssh_login" );
		return -1;
	}
	if(isnull( login )){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.100259"){
			set_kb_item( name: "vt_debug_empty/" + oid, value: oid + "#-#login#-#ssh_login" );
		}
	}
	sess = ssh_connect( socket: socket, keytype: keytype );
	if(!sess){
		return -1;
	}
	_last_libssh_sess = sess;
	auth_successful = ssh_userauth( session: sess, login: login, password: password, privatekey: priv, passphrase: passphrase );
	if(isnull( auth_successful ) || auth_successful){
		return -1;
	}
	ssh_supported_authentication = ssh_get_supported_authentication( sess_id: sess );
	if(ssh_supported_authentication == "" || ssh_supported_authentication == "none" || ord( ssh_supported_authentication ) == "0"){
		return -2;
	}
	return 0;
}
func del_esc_seq( data ){
	var data;
	data = ereg_replace( pattern: "\x1b\x5b[0-9;]*[mK]", replace: "", string: data );
	data = ereg_replace( pattern: "\x1b\x3e", replace: "", string: data );
	data = ereg_replace( pattern: "[\r|\x07|\x1b|\x08|\\[|\x0c]", replace: "", string: data );
	return data;
}
func ssh_read_from_shell( sess, pattern, timeout, retry ){
	var sess, pattern, timeout, retry;
	var x, buf, len, t, ret;
	if(!sess){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#sess#-#ssh_read_from_shell" );
		return FALSE;
	}
	if(!timeout){
		timeout = 15;
	}
	if(!retry){
		retry = 3;
	}
	x = 1;
	for(;TRUE;){
		buf = del_esc_seq( data: ssh_shell_read( sess ) );
		len = strlen( buf );
		t++;
		if( len > 0 ){
			ret += buf;
			x = 1;
		}
		else {
			if(x++ >= retry){
				return ret;
			}
		}
		if(pattern && ret){
			if(eregmatch( pattern: pattern, string: ret )){
				return ret;
			}
		}
		if(t >= timeout){
			return ret;
		}
		sleep( 1 );
		if(ContainsString( ret, "Press Enter to continue" ) || ContainsString( ret, "--More" ) || ContainsString( ret, "<--- More --->" )){
			ssh_shell_write( session: sess, cmd: "\n" );
		}
	}
	return ret;
}
func ssh_cmd_pty( sess, cmd, pattern, timeout, retry, clear_buffer ){
	var sess, cmd, pattern, timeout, retry, clear_buffer;
	var extra_cmd, c, ret;
	if(!cmd){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cmd#-#ssh_cmd_pty" );
		return FALSE;
	}
	if(!sess){
		sess = _last_libssh_sess;
	}
	if(!sess || int( sess ) < 1){
		return FALSE;
	}
	if(!sess = ssh_shell_open( sess )){
		return FALSE;
	}
	if(isnull( timeout )){
		timeout = 15;
	}
	if(isnull( retry )){
		retry = 3;
	}
	if(extra_cmd = get_kb_item( "ssh/send_extra_cmd" )){
		ssh_shell_write( session: sess, cmd: extra_cmd );
		sleep( 5 );
	}
	if(isnull( clear_buffer )){
		if(get_kb_item( "ssh/force/clear_buffer" )){
			clear_buffer = TRUE;
		}
	}
	if(clear_buffer){
		for(;TRUE;){
			c = ssh_read_from_shell( sess: sess, timeout: 3, retry: 3 );
			if(strlen( c ) <= 0){
				break;
			}
		}
	}
	ssh_shell_write( session: sess, cmd: cmd + "\n" );
	sleep( 1 );
	ret = ssh_read_from_shell( sess: sess, pattern: pattern, timeout: timeout, retry: retry );
	ssh_shell_close( sess );
	if(!ret){
		return FALSE;
	}
	ret = str_replace( string: ret, find: cmd + "\n", replace: "" );
	return ( ret );
}
func ssh_cmd( socket, cmd, timeout, nosh, nosu, return_errors, return_linux_errors_only, pty, pattern, retry, clear_buffer, force_reconnect, ignore_force_pty ){
	var socket, cmd, timeout, nosh, nosu, return_errors, return_linux_errors_only, pty, pattern, retry, clear_buffer, force_reconnect, ignore_force_pty;
	var elevate_privs, use_su, su_user, nolang_sh, debug_enabled, debug_str, sess, ret_ssh_buf, err;
	if(!cmd){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cmd#-#ssh_cmd" );
		return;
	}
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ssh_cmd" );
		return;
	}
	elevate_privs = ssh_elevate_privs_enabled_nd_working();
	if(!nosu){
		use_su = get_kb_item( "ssh/lsc/use_su" );
		if(use_su && ContainsString( use_su, "yes" ) && !elevate_privs){
			su_user = get_kb_item( "ssh/lsc/su_user" );
			cmd = str_replace( string: cmd, find: "'", replace: "\'\"\'\"\'" );
			cmd = "su - " + su_user + " -s /bin/bash -c '" + cmd + "'";
			nosh = TRUE;
		}
	}
	if(!nosh){
		if( get_kb_item( "ssh/force/nosh" ) ) {
			nosh = TRUE;
		}
		else {
			if(get_kb_item( "ssh/force/nolang_sh" )){
				nolang_sh = TRUE;
			}
		}
	}
	if(get_kb_item( "ssh/no_linux_shell" )){
		nosh = TRUE;
		if(IsMatchRegexp( cmd, "^(/s?bin|cat |perl |cmd /|netstat |find |which |whereis |locate |dmidecode |grep )" )){
			return FALSE;
		}
	}
	if(!nosh){
		cmd = str_replace( string: cmd, find: "'", replace: "\"" );
		if( nolang_sh ) {
			cmd = NASLString( "/bin/sh -c ", "'", cmd, "'" );
		}
		else {
			cmd = NASLString( "/bin/sh -c ", "'LANG=C; LC_ALL=C; ", cmd, "'" );
		}
	}
	if(!pty){
		if(!ignore_force_pty && get_kb_item( "ssh/force/pty" )){
			pty = TRUE;
		}
	}
	if(isnull( pty )){
		pty = FALSE;
	}
	if(isnull( nosh )){
		nosh = FALSE;
	}
	debug_enabled = get_kb_item( "global_settings/ssh/debug" );
	if(debug_enabled){
		debug_str = "\n---------------------------------------------------------\n" + "SSH DEBUG:\n" + "IP:   " + get_host_ip() + "\n" + "PTY:  " + pty + "\n" + "NOSH: " + nosh + "\n" + "CMD:  " + cmd + "\n";
	}
	if(get_kb_item( "ssh/force/reconnect" ) || force_reconnect){
		ssh_close_connection( socket: socket );
		socket = ssh_login_or_reuse_connection();
		if(!socket){
			if(debug_enabled){
				debug_str += "NOTE: Failed to reconnect to target host";
				debug_str += "\n---------------------------------------------------------";
				display( debug_str );
			}
			return;
		}
	}
	sess = ssh_session_id_from_sock( socket );
	if( sess ){
		if( elevate_privs ) {
			ret_ssh_buf = ssh_cmd_with_su( sess: sess, cmd: cmd, pty: pty, pattern: pattern, timeout: timeout, retry: retry, clear_buffer: clear_buffer );
		}
		else {
			if( pty ) {
				ret_ssh_buf = ssh_cmd_pty( sess: sess, cmd: cmd, pattern: pattern, timeout: timeout, retry: retry, clear_buffer: clear_buffer );
			}
			else {
				ret_ssh_buf = ssh_request_exec( session: sess, cmd: cmd, stdout: 0, stderr: 0 );
			}
		}
		ret_ssh_buf = chomp( ret_ssh_buf );
		if(!ret_ssh_buf){
			if(debug_enabled && !elevate_privs){
				debug_str += "RES:  (empty / no response)";
				debug_str += "\n---------------------------------------------------------";
				display( debug_str );
			}
			return NULL;
		}
		if(debug_enabled && !elevate_privs){
			debug_str += "\nRES (before clean up):\n--- added separator start ---\n" + ret_ssh_buf + "\n--- added separator end   ---\n";
		}
		ret_ssh_buf = ssh_clean_cmd_from_err( data: ret_ssh_buf );
		if(!ret_ssh_buf){
			if(debug_enabled && !elevate_privs){
				debug_str += "RES:  (empty after clean up)";
				debug_str += "\n---------------------------------------------------------";
				display( debug_str );
			}
			return NULL;
		}
		if(debug_enabled && !elevate_privs){
			debug_str += "\nRES (after clean up):\n--- added separator start ---\n" + ret_ssh_buf + "\n--- added separator end   ---\n";
			display( debug_str );
		}
		if(ContainsString( ret_ssh_buf, "Cmd exec error" ) || ContainsString( ret_ssh_buf, "error: unknown command" ) || ContainsString( ret_ssh_buf, "Unknown command: " ) || ContainsString( ret_ssh_buf, "Invalid input detected" ) || ContainsString( ret_ssh_buf, ": No such command" ) || ContainsString( ret_ssh_buf, "-----unknown keyword " ) || ContainsString( ret_ssh_buf, "Unknown action 0" ) || ContainsString( ret_ssh_buf, "Line has invalid autocommand" ) || ContainsString( ret_ssh_buf, "Error: Unrecognized command found" ) || ContainsString( ret_ssh_buf, "Invalid command" ) || ContainsString( ret_ssh_buf, "is not a recognized command" ) || ContainsString( ret_ssh_buf, "not found.  Type '?' for a list of commands" ) || ContainsString( ret_ssh_buf, "Syntax Error: unexpected argument" ) || ContainsString( ret_ssh_buf, "> % Command not found" )){
			set_kb_item( name: "ssh/force/nosh", value: TRUE );
			if(!return_errors){
				return "";
			}
			if(return_linux_errors_only){
				return "";
			}
		}
		if(err = egrep( string: ret_ssh_buf, pattern: "(: error while loading shared libraries: |Segmentation fault \\(core dumped\\))", icase: TRUE )){
			set_kb_item( name: "ssh/login/broken_binaries", value: chomp( cmd ) + "##----##----##" + chomp( err ) );
			if(!return_errors){
				return "";
			}
		}
		if(IsMatchRegexp( ret_ssh_buf, ": not found" ) || IsMatchRegexp( ret_ssh_buf, ": Permission denied" ) || IsMatchRegexp( ret_ssh_buf, ": cannot open " ) || IsMatchRegexp( ret_ssh_buf, ": can't cd to" ) || IsMatchRegexp( ret_ssh_buf, "No such file or directory" ) || IsMatchRegexp( ret_ssh_buf, "command not found" ) || IsMatchRegexp( ret_ssh_buf, ": Not a directory" ) || IsMatchRegexp( ret_ssh_buf, "^package [^ ]+ is not installed$" ) || IsMatchRegexp( ret_ssh_buf, "which: no [^ ]+ in \\([^)]+\\)" )){
			if(!return_errors){
				return "";
			}
		}
		return chomp( ret_ssh_buf );
	}
	else {
		if(debug_enabled){
			debug_str += "NOTE: Failed to open an SSH session to the target host";
			debug_str += "\n---------------------------------------------------------";
			display( debug_str );
		}
	}
	return NULL;
}
func ssh_elevate_privs_enabled_nd_working(  ){
	var elevate_privs;
	if( !isnull( __ssh_elevate_privs_enabled_nd_working ) ){
		elevate_privs = __ssh_elevate_privs_enabled_nd_working;
	}
	else {
		if( !get_kb_item( "login/SSH/priv/failed" ) && ssh_kb_privlogin() ) {
			elevate_privs = TRUE;
		}
		else {
			elevate_privs = FALSE;
		}
		__ssh_elevate_privs_enabled_nd_working = elevate_privs;
	}
	return elevate_privs;
}
func ssh_cmd_with_su( sess, cmd, pty, pattern, timeout, retry, clear_buffer ){
	var sess, cmd, pty, pattern, timeout, retry, clear_buffer;
	var debug_enabled, debug_str, shell, priv_user, su_cmd, ret, priv_password, c, split_ret, _split_item;
	if(!cmd){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cmd#-#ssh_cmd_with_su" );
		return FALSE;
	}
	if(!sess){
		sess = _last_libssh_sess;
	}
	if(!sess || int( sess ) < 1){
		return FALSE;
	}
	if(isnull( pty )){
		pty = FALSE;
	}
	debug_enabled = get_kb_item( "global_settings/ssh/debug" );
	if(debug_enabled){
		debug_str = "\n---------------------------------------------------------\n" + "SSH DEBUG (elevating privileges method / feature enabled):\n" + "IP:   " + get_host_ip() + "\n" + "PTY:  " + pty + "\n" + "CMD:  " + cmd + "\n";
	}
	if(!shell = ssh_shell_open( session: sess, pty: TRUE )){
		if(debug_enabled){
			debug_str += "NOTE: Failed to open interactive shell in open session";
			debug_str += "\n---------------------------------------------------------";
			display( debug_str );
		}
		return FALSE;
	}
	if(!priv_user = ssh_kb_privlogin()){
		ssh_shell_close( shell );
		return FALSE;
	}
	if(isnull( timeout )){
		timeout = 15;
	}
	if(isnull( retry )){
		retry = 3;
	}
	su_cmd = "su - " + priv_user + "\n";
	ssh_shell_write( session: shell, cmd: su_cmd );
	ret = ssh_read_from_shell( sess: shell, timeout: timeout, retry: retry );
	ret = chomp( ret );
	if(!ret || !ContainsString( ret, "Password:" )){
		ssh_shell_close( shell );
		if(debug_enabled){
			debug_str += "NOTE: Failed to read \"Password:\" string from response\n";
			if( !ret ) {
				debug_str += "RES:  (empty / no response)";
			}
			else {
				debug_str += "RES:\n--- added separator start ---\n" + ret + "\n--- added separator end   ---";
			}
			debug_str += "\n---------------------------------------------------------";
			display( debug_str );
		}
		return FALSE;
	}
	if(!priv_password = ssh_kb_privpassword()){
		ssh_shell_close( shell );
		return FALSE;
	}
	ssh_shell_write( session: shell, cmd: priv_password + "\n" );
	if(isnull( clear_buffer )){
		if(get_kb_item( "ssh/force/clear_buffer" )){
			clear_buffer = TRUE;
		}
	}
	if(clear_buffer || !pty){
		for(;TRUE;){
			c = ssh_read_from_shell( sess: shell, timeout: 3, retry: 3 );
			if(strlen( c ) <= 0){
				break;
			}
		}
	}
	ssh_shell_write( session: shell, cmd: cmd + "\n" );
	sleep( 1 );
	ret = ssh_read_from_shell( sess: shell, timeout: timeout, retry: retry, pattern: pattern );
	ret = chomp( ret );
	ssh_shell_close( shell );
	if(!ret){
		if(debug_enabled){
			debug_str += "NOTE: Failed to read response from open shell / session\n";
			if( pattern ) {
				debug_str += "RES:  (empty / no response / received response doesn\'t match given pattern \"" + pattern + "\")";
			}
			else {
				debug_str += "RES:  (empty / no response)";
			}
			debug_str += "\n---------------------------------------------------------";
			display( debug_str );
		}
		return FALSE;
	}
	if(debug_enabled){
		debug_str += "\nRES (before clean up):\n--- added separator start ---\n" + ret + "\n--- added separator end   ---\n";
	}
	ret = str_replace( string: ret, find: cmd + "\n", replace: "" );
	if(!pty && ret){
		split_ret = split( buffer: ret, keep: FALSE );
		if(max_index( split_ret ) > 0){
			ret = "";
			for(_split_item = 0;_split_item < max_index( split_ret ) - 1;_split_item++){
				ret += split_ret[_split_item] + "\n";
			}
		}
	}
	ret = chomp( ret );
	if(debug_enabled){
		if( !ret ) {
			debug_str += "\nRES:  (empty after clean up)";
		}
		else {
			debug_str += "\nRES (after clean up):\n--- added separator start ---\n" + ret + "\n--- added separator end   ---";
		}
		debug_str += "\n---------------------------------------------------------";
		display( debug_str );
	}
	return ( ret );
}
func ssh_reuse_connection(  ){
	}
func ssh_close_connection(  ){
	}
func ssh_login_or_reuse_connection(  ){
	var login, password, priv, passphrase, sess, auth_successful, soc;
	login = kb_ssh_login();
	password = kb_ssh_password();
	priv = kb_ssh_privatekey();
	passphrase = kb_ssh_passphrase();
	if(!login && ( !password && !priv )){
		return 0;
	}
	sess = ssh_connect();
	if(!sess){
		return 0;
	}
	auth_successful = ssh_userauth( session: sess, login: login, password: password, privatekey: priv, passphrase: passphrase );
	if(isnull( auth_successful ) || auth_successful){
		ssh_disconnect( sess );
		last_sess = 0;
		return 0;
	}
	soc = ssh_get_sock( sess );
	_last_libssh_sess = sess;
	return soc;
}
func ssh_cmd_exec( cmd ){
	var cmd;
	var login, password, priv, passphrase, sess, auth_successful, result;
	if(!cmd){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#cmd#-#ssh_cmd_exec" );
		return;
	}
	login = kb_ssh_login();
	password = kb_ssh_password();
	priv = kb_ssh_privatekey();
	passphrase = kb_ssh_passphrase();
	sess = ssh_connect();
	if(!sess){
		return NULL;
	}
	auth_successful = ssh_userauth( session: sess, login: login, password: password, privatekey: priv, passphrase: passphrase );
	if(isnull( auth_successful ) || auth_successful){
		ssh_disconnect( sess );
		return NULL;
	}
	result = ssh_request_exec( session: sess, cmd: cmd, stdout: 1, stderr: 1 );
	ssh_disconnect( sess );
	return chomp( result );
}
func ssh_hack_get_server_version( socket ){
	var socket;
	var buf;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#ssh_hack_get_server_version" );
		return;
	}
	buf = recv_line( socket: socket, length: 1024 );
	if(!buf){
		ssh_set_error( msg: "The scanner did not receive server's version" );
		return 0;
	}
	if(!ssh_verify_server_ident( data: buf )){
		ssh_set_error( msg: "Remote service is not a valid SSH service" );
		return 0;
	}
	if( ContainsString( buf, "\r\n" ) ) {
		buf = buf - "\r\n";
	}
	else {
		buf = buf - "\n";
	}
	return buf;
}
func ssh_reconnect( sock ){
	var sock;
	if(!sock){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#ssh_reconnect" );
		return;
	}
	ssh_disconnect( ssh_session_id_from_sock( sock ) );
	sleep( 1 );
	sock = ssh_login_or_reuse_connection();
	if(!sock){
		return;
	}
	return sock;
}
func ssh_get_port( default, nodefault, ignore_unscanned ){
	var default, nodefault, ignore_unscanned;
	var port;
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#ssh_get_port" );
		exit( 0 );
	}
	port = get_kb_item( "Services/ssh" );
	if(port){
		default = port;
	}
	if(!default){
		exit( 0 );
	}
	if(port_is_marked_fragile( port: default )){
		exit( 0 );
	}
	if(!get_port_state( default )){
		exit( 0 );
	}
	return default;
}
func ssh_get_ports( default_port_list, ignore_unscanned ){
	var default_port_list, ignore_unscanned;
	var final_port_list, check_port_list, default_ports, num_ports, ports, _port;
	final_port_list = make_list();
	check_port_list = make_list();
	default_ports = make_list( 22 );
	num_ports = 0;
	ports = get_kb_list( "Services/ssh" );
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
		final_port_list = make_list( final_port_list,
			 _port );
	}
	return final_port_list;
}
func ssh_broken_random_login( port ){
	var port;
	var login_banner, banner, count, logins, i, user, pass, soc, login;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ssh_broken_random_login" );
		return NULL;
	}
	if(get_kb_item( "SSH/" + port + "/broken/random_login" )){
		return TRUE;
	}
	if(get_kb_item( "SSH/" + port + "/broken/random_login/checked" )){
		return FALSE;
	}
	login_banner = ssh_get_login_banner( port: port );
	banner = ssh_get_serverbanner( port: port );
	count = 0;
	logins = 0;
	if(get_kb_item( "teamspeak3_server/detected" ) && banner && IsMatchRegexp( banner, "^SSH-2.0-libssh" )){
		set_kb_item( name: "SSH/" + port + "/broken/random_login", value: TRUE );
		return TRUE;
	}
	for(i = 1;i < 3;i++){
		if( i == 1 && ( IsMatchRegexp( banner, "(cisco|FIPS User Access Verification)" ) || ContainsString( login_banner, "Cisco Systems, Inc. All rights Reserved" ) ) ){
			user = "Anonymous";
			pass = "";
		}
		else {
			user = rand_str( length: 7 + i, charset: "abcdefghiklmnopqrstuvwxyz" );
			pass = rand_str( length: 7 + i, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz" );
		}
		if(!soc = open_sock_tcp( port )){
			sleep( 1 );
			continue;
		}
		count++;
		login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
		close( soc );
		if(login == 0){
			logins++;
		}
		sleep( 1 );
	}
	if(count > 0){
		set_kb_item( name: "SSH/" + port + "/broken/random_login/checked", value: TRUE );
	}
	if(logins > 0){
		set_kb_item( name: "SSH/" + port + "/broken/random_login", value: TRUE );
		return TRUE;
	}
	if( count == 0 ) {
		return NULL;
	}
	else {
		return FALSE;
	}
}
func ssh_find_bin( prog_name, sock ){
	var prog_name, sock;
	var cl, r, where, _r, final_list, which;
	if(get_kb_item( "ssh/no_linux_shell" )){
		return NULL;
	}
	if(!prog_name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#prog_name#-#ssh_find_bin" );
		return NULL;
	}
	if(!sock){
		sock = ssh_login_or_reuse_connection();
	}
	if(!sock){
		return NULL;
	}
	cl = ssh_check_locate( sock: sock );
	if( cl ) {
		r = split( ssh_cmd( socket: sock, cmd: "locate -ei *bin/" + prog_name, timeout: 60 ) );
	}
	else {
		r = NULL;
	}
	if(!r || !ContainsString( r, "bin/" + prog_name )){
		where = ssh_cmd( socket: sock, cmd: "whereis -b " + prog_name, timeout: 60 );
		if( ContainsString( where, prog_name + ":" ) && ContainsString( where, "bin/" + prog_name ) ){
			r = split( buffer: substr( where - ( prog_name + ":" ), 1 ), sep: " " );
			final_list = make_list();
			for _r in r {
				if(ContainsString( _r, "bin/" + prog_name )){
					final_list = make_list( final_list,
						 _r );
				}
			}
			if( max_index( final_list ) > 0 ) {
				r = final_list;
			}
			else {
				r = NULL;
			}
		}
		else {
			r = NULL;
		}
	}
	if(!r){
		which = ssh_cmd( socket: sock, cmd: "which -a " + prog_name, timeout: 60 );
		if(!which || !ContainsString( which, "bin/" ) || ContainsString( which, "which: no " + prog_name )){
			return NULL;
		}
		if( eregmatch( string: which, pattern: "^/.*bin/" + prog_name, icase: FALSE ) ) {
			r = split( which );
		}
		else {
			return NULL;
		}
	}
	return ( r );
}
func ssh_find_file( file_name, useregex, sock, follow_symlinks ){
	var file_name, useregex, sock, follow_symlinks;
	var res, lparam, use_find, descend_directories, search_exclude_paths, cl, _res, tmp_list;
	var final_list, _item, maxdepth, cmd, check_pattern, start, end, current_timeout;
	if(get_kb_item( "ssh/no_linux_shell" )){
		return;
	}
	if(!file_name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#file_name#-#ssh_find_file" );
		return;
	}
	res = NULL;
	if( useregex ) {
		lparam = "-ei --regex";
	}
	else {
		lparam = "-ei";
	}
	use_find = get_kb_item( "ssh/lsc/enable_find" );
	descend_directories = get_kb_item( "ssh/lsc/descend_ofs" );
	if(isnull( use_find )){
		use_find = "yes";
	}
	if(isnull( descend_directories )){
		descend_directories = "yes";
	}
	if(!search_exclude_paths = get_kb_item( "ssh/lsc/search_exclude_paths" )){
		search_exclude_paths = "^/(afs|dev|media|mnt|net|run|sfs|sys|tmp|udev|var/(backups|cache|lib|local|lock|log|lost\\+found|mail|opt|run|spool|tmp)|etc/init\\.d|usr/share/doc)";
	}
	if(!sock){
		sock = ssh_login_or_reuse_connection();
	}
	if(!sock){
		return NULL;
	}
	cl = ssh_check_locate( sock: sock );
	if(cl){
		res = ssh_cmd( socket: sock, cmd: "locate " + lparam + " \"" + file_name + "\"", timeout: 60 );
		res = chomp( res );
		if( res && res[0] == "/" ){
			_res = split( res );
			tmp_list = make_list();
			final_list = make_list();
			for _item in _res {
				_item = chomp( _item );
				if(!_item){
					continue;
				}
				if( useregex ){
					if(egrep( string: _item, pattern: file_name, icase: FALSE )){
						tmp_list = make_list( tmp_list,
							 _item );
					}
				}
				else {
					if(ContainsString( _item, file_name )){
						tmp_list = make_list( tmp_list,
							 _item );
					}
				}
			}
			if( search_exclude_paths && search_exclude_paths != "None" ){
				for _item in tmp_list {
					if(!egrep( string: _item, pattern: search_exclude_paths, icase: TRUE )){
						final_list = make_list( final_list,
							 _item );
					}
				}
			}
			else {
				final_list = tmp_list;
			}
			if( max_index( final_list ) > 0 ) {
				res = final_list;
			}
			else {
				res = NULL;
			}
		}
		else {
			res = NULL;
		}
	}
	if(!res && ContainsString( use_find, "yes" )){
		cmd = "find \"/\"";
		if(ContainsString( descend_directories, "no" )){
			cmd += " -xdev";
		}
		if(!maxdepth = get_kb_item( "ssh/lsc/find_maxdepth" )){
			maxdepth = "12";
		}
		if(maxdepth == "zero"){
			maxdepth = "0";
		}
		check_pattern = " -maxdepth " + maxdepth + " -mindepth 1";
		cmd += check_pattern;
		cmd += " -regextype posix-extended";
		if(search_exclude_paths && search_exclude_paths != "None"){
			cmd += " -regex \"" + search_exclude_paths + "\" -prune -o";
		}
		cmd += " -path \"*/proc\" -prune -o";
		if( useregex ) {
			cmd += " -regex \".*";
		}
		else {
			cmd += " -path \"*";
		}
		cmd += file_name + "\"";
		cmd += " -a -type f";
		if(follow_symlinks){
			cmd += ",l";
		}
		cmd += " -print 2>/dev/null";
		start = unixtime();
		res = ssh_cmd( socket: sock, cmd: cmd, timeout: 60 );
		end = unixtime();
		res = chomp( res );
		if( res && res[0] == "/" && !ContainsString( res, check_pattern ) ){
			_res = split( res );
			final_list = make_list();
			for _item in _res {
				_item = chomp( _item );
				if(!_item){
					continue;
				}
				if( useregex ){
					if(egrep( string: _item, pattern: file_name, icase: FALSE )){
						final_list = make_list( final_list,
							 _item );
					}
				}
				else {
					if(ContainsString( _item, file_name )){
						final_list = make_list( final_list,
							 _item );
					}
				}
			}
			if( max_index( final_list ) > 0 ) {
				res = final_list;
			}
			else {
				res = NULL;
			}
		}
		else {
			res = NULL;
		}
		current_timeout = get_kb_item( "ssh/lsc/find_timeout" );
		if(end - start > 29){
			current_timeout++;
			replace_kb_item( name: "ssh/lsc/find_timeout", value: current_timeout );
		}
		if(ContainsString( descend_directories, "yes" ) && current_timeout >= 3){
			replace_kb_item( name: "ssh/lsc/descend_ofs", value: "no" );
		}
	}
	if(!res){
		return NULL;
	}
	return res;
}
func ssh_get_bin_version( full_prog_name, version_argv, ver_pattern, sock ){
	var full_prog_name, version_argv, ver_pattern, sock;
	var r, loc_version;
	if(get_kb_item( "ssh/no_linux_shell" )){
		return;
	}
	if(!full_prog_name){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#full_prog_name#-#ssh_get_bin_version" );
		return;
	}
	if(!version_argv){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#version_argv#-#ssh_get_bin_version" );
	}
	if(!ver_pattern){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#ver_pattern#-#ssh_get_bin_version" );
	}
	full_prog_name = chomp( full_prog_name );
	version_argv = chomp( version_argv );
	if(!sock){
		sock = ssh_login_or_reuse_connection();
	}
	if(sock){
		r = ssh_cmd( socket: sock, cmd: full_prog_name + " " + version_argv, timeout: 60 );
	}
	if(!r){
		return;
	}
	loc_version = eregmatch( pattern: ver_pattern, string: r );
	if(loc_version != NULL){
		loc_version[max_index( loc_version )] = r;
	}
	return ( loc_version );
}
func ssh_check_locate( sock ){
	var sock;
	var r;
	if(!sock){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#sock#-#ssh_check_locate" );
		return;
	}
	if(get_kb_item( "ssh/locate/available" )){
		return TRUE;
	}
	if(get_kb_item( "ssh/no_linux_shell" )){
		return FALSE;
	}
	if(get_kb_item( "ssh/locate/broken" )){
		return FALSE;
	}
	r = ssh_cmd( socket: sock, cmd: "locate -S", timeout: 60, return_errors: TRUE, return_linux_errors_only: TRUE );
	if(ContainsString( r, "locate: invalid option -- S" ) || ContainsString( r, "locate: unknown option -- S" )){
		r = ssh_cmd( socket: sock, cmd: "locate /bin/bash", timeout: 60 );
		if( !ContainsString( r, "locate:" ) && ContainsString( r, "/bin/bash" ) ){
			set_kb_item( name: "ssh/locate/available", value: TRUE );
			return TRUE;
		}
		else {
			if(!ContainsString( r, "locate:" )){
				r = ssh_cmd( socket: sock, cmd: "locate /bin/sh", timeout: 60 );
				if(!ContainsString( r, "locate:" ) && ContainsString( r, "/bin/sh" )){
					set_kb_item( name: "ssh/locate/available", value: TRUE );
					return TRUE;
				}
			}
		}
	}
	if(( !ContainsString( r, "Database /" ) || ( !ContainsString( r, "bytes" ) && !ContainsString( r, "Compression" ) && !ContainsString( r, "Filenames" ) && !ContainsString( r, "file names" ) ) ) || ContainsString( tolower( r ), "command not found" ) || ContainsString( r, "locate: not found" ) || ContainsString( r, "locate:" )){
		if(!r){
			r = "No response received from the remote SSH service.";
		}
		set_kb_item( name: "ssh/locate/broken", value: r );
		return FALSE;
	}
	set_kb_item( name: "ssh/locate/available", value: TRUE );
	return TRUE;
}
func ssh_get_serverbanner( port ){
	var port;
	var banner, soc;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ssh_get_serverbanner" );
		return;
	}
	if(!get_port_state( port )){
		return;
	}
	banner = get_kb_item( "SSH/server_banner/" + port );
	if(banner){
		return banner;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		return;
	}
	banner = ssh_hack_get_server_version( socket: soc );
	close( soc );
	if(banner){
		replace_kb_item( name: "SSH/server_banner/" + port, value: banner );
	}
	return banner;
}
func ssh_clean_cmd_from_err( data ){
	var data;
	if(!data){
		return data;
	}
	data = ereg_replace( string: data, pattern: "^([a-zA-Z]+: )?Could not chdir to home directory [^:]+: (No such file or directory|Permission denied)[\r\n]*", replace: "" );
	data = ereg_replace( string: data, pattern: "^xcode-select: error: no developer tools were found at \'/Applications/Xcode\\.app\', and no install could be requested \\(perhaps no UI is present\\), please install manually from \'developer\\.apple\\.com\'\\.[\r\n]*", replace: "" );
	return data;
}
func ssh_check_file_existence( sock, file ){
	var sock, file;
	var cmd, file_exists;
	if(!sock){
		sock = ssh_login_or_reuse_connection();
	}
	if(!file){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#file#-#ssh_check_file_existence" );
		return;
	}
	cmd = "[ -f " + file + " ] && echo \"TRUE\" || echo \"FALSE\"";
	file_exists = ssh_cmd( cmd: cmd, socket: sock );
	if( file_exists == "TRUE" ) {
		return TRUE;
	}
	else {
		if( file_exists == "FALSE" ) {
			return FALSE;
		}
		else {
			return;
		}
	}
}
func ssh_check_file_readable( sock, file ){
	var sock, file;
	var cmd, file_readable;
	if(!sock){
		sock = ssh_login_or_reuse_connection();
	}
	if(!file){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#file#-#ssh_check_file_existence" );
		return;
	}
	cmd = "[ -r " + file + " ] && echo \"TRUE\" || echo \"FALSE\"";
	file_readable = ssh_cmd( cmd: cmd, socket: sock );
	if( file_readable == "TRUE" ) {
		return TRUE;
	}
	else {
		if( file_readable == "FALSE" ) {
			return FALSE;
		}
		else {
			return;
		}
	}
}
func ssh_get_login_banner( port, sock, login, passwd, privkey, keypassphrase ){
	var port, sock, login, passwd, privkey, keypassphrase;
	var banner, nosock, vt_strings, sess_id;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#ssh_get_login_banner" );
		return;
	}
	banner = get_kb_item( "SSH/login_banner/" + port );
	if(banner){
		if( banner != "None Available" ) {
			return banner;
		}
		else {
			return FALSE;
		}
	}
	if(!sock){
		if(!get_port_state( port )){
			return;
		}
		sock = open_sock_tcp( port );
		if(!sock){
			return;
		}
		nosock = TRUE;
	}
	if(!login || !passwd){
		vt_strings = get_vt_strings();
		if(!login){
			login = vt_strings["default"];
		}
		if(!passwd && !privkey){
			passwd = vt_strings["default"];
		}
	}
	ssh_login( socket: sock, login: login, password: passwd, priv: privkey, passphrase: keypassphrase );
	sess_id = ssh_session_id_from_sock( sock );
	if(sess_id){
		_last_libssh_sess = sess_id;
	}
	banner = ssh_get_issue_banner( _last_libssh_sess );
	if(nosock){
		close( sock );
	}
	banner = chomp( banner );
	if( strlen( banner ) > 0 ){
		set_kb_item( name: "SSH/login_banner/" + port, value: banner );
		return banner;
	}
	else {
		set_kb_item( name: "SSH/login_banner/" + port, value: "None Available" );
		return FALSE;
	}
}
func ssh_verify_server_ident( data ){
	var data;
	data = chomp( data );
	if(!data){
		return FALSE;
	}
	if(ereg( string: data, pattern: "^SSH-*[0-9]\\.*[0-9]-*[^\\n]", icase: FALSE )){
		return TRUE;
	}
	return FALSE;
}

