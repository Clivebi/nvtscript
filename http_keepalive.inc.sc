var __ka_port, __ka_sockets, __ka_last_request, __ka_enabled_status;
__ka_port = 0;
__ka_sockets = make_array();
__ka_last_request = make_array();
__ka_enabled_status = make_array();
var _http_ka_debug;
_http_ka_debug = FALSE;
var _http_ua_include_oid;
_http_ua_include_oid = FALSE;
var optimize_test_enabled;
optimize_test_enabled = get_preference( "optimize_test" );
func http_keepalive_check_connection( headers, host, port ){
	var headers, host, port;
	if(!headers){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#headers#-#http_keepalive_check_connection" );
		return NULL;
	}
	if(egrep( pattern: "^Connection\\s*:\\s*Close", string: headers, icase: TRUE )){
		http_keepalive_reopen_connection( host: host, port: port );
	}
	return NULL;
}
func http_enable_keepalive( port, host ){
	var port, host;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_enable_keepalive" );
		return NULL;
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_enable_keepalive" );
	}
	__ka_enabled_status[host + "#--#" + port] = 1;
	__ka_port = port;
	__ka_sockets[host + "#--#" + port] = http_open_socket( port );
	return NULL;
}
func http_keepalive_enabled( port, host ){
	var port, host;
	var key, kb, useragent, host, req, soc, r;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_keepalive_enabled" );
		return -1;
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_keepalive_enabled" );
	}
	key = strcat( "www/", host, "/", port, "/keepalive" );
	kb = get_kb_item( key );
	if( kb == "yes" ){
		http_enable_keepalive( port: port, host: host );
		return ( 1 );
	}
	else {
		if(kb == "no"){
			return ( 0 );
		}
	}
	useragent = http_get_user_agent();
	host = http_host_name( port: port );
	soc = http_open_socket( port );
	if(!soc){
		return -1;
	}
	req = strcat( "GET / HTTP/1.1\r\n", "Connection: Keep-Alive\r\n", "Host: ", host, "\r\n", "Pragma: no-cache\r\n", "User-Agent: ", useragent, "\r\n\r\n" );
	send( socket: soc, data: req );
	r = http_recv( socket: soc );
	if( egrep( pattern: "^Keep-Alive\\s*:.*", string: r, icase: TRUE ) ){
		http_close_socket( soc );
		set_kb_item( name: key, value: "yes" );
		http_enable_keepalive( port: port, host: host );
		return ( 1 );
	}
	else {
		send( socket: soc, data: req );
		r = http_recv( socket: soc );
		http_close_socket( soc );
		if(strlen( r )){
			set_kb_item( name: key, value: "yes" );
			http_enable_keepalive( port: port, host: host );
			return ( 1 );
		}
	}
	set_kb_item( name: key, value: "no" );
	return ( 0 );
}
func http_keepalive_recv_body( headers, port, host, bodyonly, fetch404, content_type_body_only, headersonly ){
	var headers, port, host, bodyonly, fetch404, content_type_body_only, headersonly;
	var max_length_to_receive, close_connection, length, tmp, gzip, body;
	if(!headers){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#headers#-#http_keepalive_recv_body" );
		return ( headers );
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
	}
	if(!port){
		port = __ka_port;
	}
	if(!ereg( pattern: "^HTTP/.* [0-9]{3}", string: headers )){
		http_keepalive_reopen_connection( host: host, port: port );
		return ( headers );
	}
	if(ereg( pattern: "^HEAD.*HTTP/.*", string: __ka_last_request[host + "#--#" + port] )){
		http_keepalive_check_connection( headers: headers, host: host, port: port );
		if(headersonly){
			return ( headers );
		}
		if( bodyonly ){
			return ( "" );
		}
		else {
			return ( headers );
		}
	}
	close_connection = FALSE;
	length = -1;
	max_length_to_receive = 1048576;
	if(egrep( pattern: "^Content-Length\\s*:", string: headers, icase: TRUE )){
		tmp = egrep( string: headers, pattern: "^Content-Length\\s*:\\s*[0-9]+", icase: TRUE );
		if(tmp){
			length = int( ereg_replace( string: tmp, pattern: "^Content-Length\\s*:\\s*([0-9]+).*", replace: "\\1", icase: TRUE ) );
		}
	}
	if(egrep( pattern: "^Content-Encoding\\s*:\\s*gzip", string: headers, icase: TRUE )){
		gzip = TRUE;
	}
	if(( length < 0 ) && ( egrep( pattern: "^Transfer-Encoding\\s*:\\s*chunked", string: headers, icase: TRUE ) )){
		for(;1;){
			tmp = recv_line( socket: __ka_sockets[host + "#--#" + port], length: 4096 );
			if( !tmp ) {
				length = 0;
			}
			else {
				length = hex2dec( xvalue: tmp );
			}
			if(length > max_length_to_receive){
				length = max_length_to_receive;
				close_connection = TRUE;
			}
			body = strcat( body, recv( socket: __ka_sockets[host + "#--#" + port], length: length, min: length ) );
			recv( socket: __ka_sockets[host + "#--#" + port], length: 2, min: 2 );
			if(strlen( body ) > max_length_to_receive){
				close_connection = TRUE;
			}
			if(length == 0 || close_connection){
				if( close_connection ) {
					http_keepalive_reopen_connection( host: host, port: port );
				}
				else {
					http_keepalive_check_connection( headers: headers, host: host, port: port );
				}
				if(headersonly){
					return ( headers );
				}
				if(ereg( pattern: "^HTTP/.* 404", string: headers ) && fetch404 != TRUE){
					return ( headers );
				}
				if(content_type_body_only){
					if(egrep( pattern: "^Content-Type\\s*:", string: headers, icase: TRUE )){
						if(!egrep( pattern: content_type_body_only, string: headers, icase: TRUE )){
							return ( headers );
						}
					}
				}
				if(gzip && body){
					body = http_gunzip( buf: body, onlybody: TRUE );
				}
				if( bodyonly ){
					return ( body );
				}
				else {
					return ( strcat( headers, "\r\n", body ) );
				}
			}
		}
	}
	if( length >= 0 ){
		if(length > max_length_to_receive){
			length = max_length_to_receive;
		}
		body = recv( socket: __ka_sockets[host + "#--#" + port], length: length, min: length );
		if(body && strlen( body ) == max_length_to_receive){
			close_connection = TRUE;
		}
	}
	else {
		if(_http_ka_debug){
			display( "DEBUG: ERROR - Keep Alive, but no length!!!\\n", __ka_last_request[host + "#--#" + port] );
		}
		body = recv( socket: __ka_sockets[host + "#--#" + port], length: 16384, min: 0 );
		if( IsMatchRegexp( body, "<html[^>]*>" ) && !IsMatchRegexp( body, "</html>" ) ){
			for{
				tmp = recv( socket: __ka_sockets[host + "#--#" + port], length: 16384 );
				body += tmp;
				
				if( !tmp || IsMatchRegexp( body, "</html>" ) ){
					break;
				}
			}
			if(_http_ka_debug && !IsMatchRegexp( body, "</html>" )){
				display( "DEBUG: http_keepalive_recv_body: incomplete body?\\n------------\\n", body, "\\n------------\\n" );
			}
		}
		else {
			if(!IsMatchRegexp( body, "<html[^>]*>" ) || !IsMatchRegexp( body, "</html>" )){
				close_connection = TRUE;
			}
		}
	}
	if( close_connection ) {
		http_keepalive_reopen_connection( host: host, port: port );
	}
	else {
		http_keepalive_check_connection( headers: headers, host: host, port: port );
	}
	if(headersonly){
		return ( headers );
	}
	if(ereg( pattern: "^HTTP/.* 404", string: headers ) && fetch404 != TRUE){
		return ( headers );
	}
	if(content_type_body_only){
		if(egrep( pattern: "^Content-Type\\s*:", string: headers, icase: TRUE )){
			if(!egrep( pattern: content_type_body_only, string: headers, icase: TRUE )){
				return ( headers );
			}
		}
	}
	if(gzip && body){
		body = http_gunzip( buf: body, onlybody: TRUE );
	}
	if( bodyonly ) {
		return ( body );
	}
	else {
		return ( strcat( headers, "\r\n", body ) );
	}
}
func on_exit(  ){
	var _socket_infos, socket_infos, host, port, socket_status;
	for _socket_infos in keys( __ka_sockets ) {
		socket_infos = split( buffer: _socket_infos, sep: "#--#", keep: FALSE );
		if(max_index( socket_infos ) != 2){
			continue;
		}
		host = socket_infos[0];
		port = socket_infos[1];
		socket_status = __ka_sockets[_socket_infos];
		if(socket_status){
			http_close_socket( __ka_sockets[_socket_infos] );
			__ka_sockets[_socket_infos] = 0;
		}
	}
	return NULL;
}
if(0){
	on_exit();
}
func http_keepalive_send_recv( port, data, host, bodyonly, fetch404, content_type_body_only, headersonly ){
	var port, data, host, bodyonly, fetch404, content_type_body_only, headersonly;
	var oid, soc, headers, body, n, lendata, user_agent, oid_str;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_keepalive_send_recv" );
		return NULL;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_keepalive_send_recv" );
		return NULL;
	}
	if(strlen( data ) < 8 || !IsMatchRegexp( data, "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL).*HTTP/(1\\.[01]|2)" )){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.900522" && oid != "1.3.6.1.4.1.25623.1.0.11438" && oid != "1.3.6.1.4.1.25623.1.0.10730"){
			set_kb_item( name: "vt_debug_misc/" + oid, value: oid + "#-#http_keepalive_send_recv(): Invalid HTTP request (length < 8, invalid HTTP method or missing HTTP/ header) passed in 'data' variable." );
		}
	}
	if(!ContainsString( data, "Host: " ) && !ContainsString( data, " HTTP/1.0" ) && !ContainsString( data, " HTTP/0.9" )){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.802045"){
			set_kb_item( name: "vt_debug_misc/" + oid, value: oid + "#-#http_keepalive_send_recv(): No 'Host:' header passed in 'data' variable. This might lead to issues if SNI is enabled on the remote host." );
		}
	}
	if(!IsMatchRegexp( data, "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL) (/|\\.+/|https?:|\\*).* HTTP" )){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.103293" && oid != "1.3.6.1.4.1.25623.1.0.17230" && oid != "1.3.6.1.4.1.25623.1.0.900522" && oid != "1.3.6.1.4.1.25623.1.0.11438" && oid != "1.3.6.1.4.1.25623.1.0.10730"){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_keepalive_send_recv(): URL/URI of the HTTP request passed in 'data' variable doesn't start with one of the following: '/, ./, http, *'." );
		}
	}
	if(ContainsString( data, " HTTP/1.1" ) && !egrep( pattern: "^User-Agent\\s*:.+", string: data, icase: TRUE )){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.11438"){
			data = ereg_replace( string: data, pattern: "\r\n\r\n", replace: "\r\nUser-Agent: " + http_get_user_agent() + "\r\n\r\n" );
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_keepalive_send_recv(): Using a HTTP/1.1 request without a 'User-Agent:' header passed in 'data' variable. Adding it automatically to the request." );
		}
	}
	if(_http_ua_include_oid && user_agent = egrep( pattern: "^User-Agent:.+", string: data, icase: TRUE )){
		user_agent = chomp( user_agent );
		oid_str = "(OID:" + get_script_oid() + ")";
		if(!ContainsString( user_agent, oid_str )){
			data = str_replace( string: data, find: user_agent, replace: user_agent + " " + oid_str );
		}
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
	}
	if(_http_ka_debug){
		display( "DEBUG: http_keepalive_send_recv( host: ", host, "port: ", port, ", data: ", data, ", bodyonly: ", bodyonly, " )\\n" );
	}
	if(isnull( __ka_enabled_status[host + "#--#" + port] )){
		__ka_enabled_status[host + "#--#" + port] = http_keepalive_enabled( port: port, host: host );
	}
	if(__ka_enabled_status[host + "#--#" + port] == -1){
		return NULL;
	}
	if(__ka_enabled_status[host + "#--#" + port] == 0){
		soc = http_open_socket( port );
		if(!soc){
			return NULL;
		}
		if(send( socket: soc, data: data ) <= 0){
			http_close_socket( soc );
			return NULL;
		}
		headers = http_recv_headers2( socket: soc );
		if(!headers || !ereg( pattern: "^HTTP/.* [0-9]{3}", string: headers )){
			http_close_socket( soc );
			return ( headers );
		}
		if(headersonly){
			http_close_socket( soc );
			return ( headers );
		}
		if(content_type_body_only){
			if(egrep( pattern: "^Content-Type\\s*:", string: headers, icase: TRUE )){
				if(!egrep( pattern: content_type_body_only, string: headers, icase: TRUE )){
					http_close_socket( soc );
					return ( headers );
				}
			}
		}
		if(ereg( pattern: "^HTTP/.* 404", string: headers ) && fetch404 != TRUE){
			http_close_socket( soc );
			return ( headers );
		}
		body = http_recv_body( socket: soc, headers: headers, length: 0 );
		http_close_socket( soc );
		if(body && egrep( pattern: "^Content-Encoding\\s*:\\s*gzip", string: headers, icase: TRUE )){
			body = http_gunzip( buf: body, onlybody: TRUE );
		}
		if( bodyonly ) {
			return ( body );
		}
		else {
			return ( strcat( headers, "\r\n", body ) );
		}
	}
	if(( port != __ka_port ) || ( !__ka_sockets[host + "#--#" + port] )){
		http_keepalive_reopen_connection( host: host, port: port );
		if(!__ka_sockets[host + "#--#" + port]){
			return NULL;
		}
	}
	data = ereg_replace( string: data, pattern: "Connection\\s*:\\s*Close", replace: "Connection: Keep-Alive", icase: TRUE );
	__ka_last_request[host + "#--#" + port] = data;
	n = send( socket: __ka_sockets[host + "#--#" + port], data: data );
	lendata = strlen( data );
	if(n >= lendata){
		headers = http_recv_headers2( socket: __ka_sockets[host + "#--#" + port] );
	}
	if(!headers){
		http_keepalive_reopen_connection( host: host, port: port );
		if(__ka_sockets[host + "#--#" + port] == 0){
			return NULL;
		}
		if(send( socket: __ka_sockets[host + "#--#" + port], data: data ) < lendata){
			http_close_socket( __ka_sockets[host + "#--#" + port] );
			__ka_sockets[host + "#--#" + port] = NULL;
			return NULL;
		}
		headers = http_recv_headers2( socket: __ka_sockets[host + "#--#" + port] );
	}
	if(!headers){
		return ( headers );
	}
	return http_keepalive_recv_body( headers: headers, bodyonly: bodyonly, fetch404: fetch404, content_type_body_only: content_type_body_only, headersonly: headersonly );
}
func http_is_cgi_installed_ka( port, item, host ){
	var port, item, host;
	var dirs, slash, no404, _dir, req, res;
	if(!item){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#item#-#http_is_cgi_installed_ka" );
		return NULL;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_is_cgi_installed_ka" );
		return NULL;
	}
	if(http_is_cgi_scan_disabled()){
		if(optimize_test_enabled && ContainsString( optimize_test_enabled, "yes" )){
			set_kb_item( name: "vt_debug_cgi_scanning_disabled/" + get_script_oid(), value: get_script_oid() + "#-#http_is_cgi_installed_ka()" );
		}
		exit( 0 );
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
	}
	if( item[0] != "/" ){
		dirs = http_cgi_dirs( port: port, host: host );
		slash = "/";
	}
	else {
		dirs = make_list( "" );
		slash = "";
	}
	no404 = http_get_no404_string( port: port, host: host );
	if(strlen( no404 ) >= 1){
		return NULL;
	}
	for _dir in dirs {
		if(_dir == "/"){
			_dir = "";
		}
		req = http_get( item: _dir + slash + item + "_" + rand(), port: port );
		res = http_keepalive_send_recv( port: port, host: host, data: req );
		if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 404" )){
			continue;
		}
		req = http_get( item: _dir + slash + item, port: port );
		res = http_keepalive_send_recv( port: port, host: host, data: req );
		if(!res){
			continue;
		}
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] +200 +" ) && !IsMatchRegexp( res, "Proxy-Agent\\s*:\\s*IWSS" )){
			if( no404 && ContainsString( tolower( res ), tolower( no404 ) ) ){
				continue;
			}
			else {
				return TRUE;
			}
		}
	}
	return FALSE;
}
func http_get_cache( port, item, host, fetch404 ){
	var port, item, host, fetch404;
	var key, res, req;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_get_cache" );
		return NULL;
	}
	if(!item){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#item#-#http_get_cache" );
		return NULL;
	}
	if(http_is_cgi_scan_disabled()){
		if(optimize_test_enabled && ContainsString( optimize_test_enabled, "yes" )){
			set_kb_item( name: "vt_debug_cgi_scanning_disabled/" + get_script_oid(), value: get_script_oid() + "#-#http_get_cache()" );
		}
		exit( 0 );
	}
	if( fetch404 ) {
		key = "including_404_body";
	}
	else {
		key = "excluding_404_body";
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
	}
	if(!http_is_kb_caching_disabled()){
		res = get_kb_item( "Cache/" + host + "/" + port + "/" + key + "/URL_" + item );
		if(res){
			return res;
		}
	}
	req = http_get( port: port, item: item );
	__ka_last_request[host + "#--#" + port] = req;
	res = http_keepalive_send_recv( port: port, host: host, data: req, bodyonly: FALSE, fetch404: fetch404 );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] [0-9]{3}" )){
		return NULL;
	}
	if(!http_is_kb_caching_disabled()){
		if(!IsMatchRegexp( res, "^HTTP/1\\.[01] (5(0[0-9]|1[01])|4(08|29))" )){
			replace_kb_item( name: "Cache/" + host + "/" + port + "/" + key + "/URL_" + item, value: res );
		}
	}
	return res;
}
func http_check_remote_code( default_port, host, extra_dirs, unique_dir, check_request, extra_check, check_result, command, port ){
	var default_port, host, extra_dirs, unique_dir, check_request, extra_check, check_result, command, port;
	var list, _dir, req, buf, txt_result, extra, txt_desc;
	if(!check_request){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#check_request#-#http_check_remote_code" );
		return NULL;
	}
	if(!check_result){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#check_result#-#http_check_remote_code" );
		return NULL;
	}
	if(!command){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#command#-#http_check_remote_code" );
	}
	if(http_is_cgi_scan_disabled()){
		if(optimize_test_enabled && ContainsString( optimize_test_enabled, "yes" )){
			set_kb_item( name: "vt_debug_cgi_scanning_disabled/" + get_script_oid(), value: get_script_oid() + "#-#http_check_remote_code()" );
		}
		exit( 0 );
	}
	if( !port ){
		if( default_port ){
			port = http_get_port( default: default_port );
		}
		else {
			port = http_get_port( default: 80 );
		}
	}
	else {
		if(!get_port_state( port )){
			exit( 0 );
		}
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
	}
	if( unique_dir ){
		list = make_list( unique_dir );
	}
	else {
		if( !isnull( extra_dirs ) ){
			list = nasl_make_list_unique( http_cgi_dirs( port: port, host: host ), extra_dirs );
		}
		else {
			list = make_list( http_cgi_dirs( port: port,
				 host: host ) );
		}
	}
	for _dir in list {
		if(_dir == "/"){
			_dir = "";
		}
		req = NASLString( _dir, check_request );
		req = http_get( item: req, port: port );
		buf = http_keepalive_send_recv( port: port, host: host, data: req );
		if(!buf){
			continue;
		}
		txt_result = egrep( pattern: check_result, string: buf );
		if( extra_check ){
			extra = FALSE;
			if(egrep( pattern: extra_check, string: buf )){
				extra = TRUE;
			}
		}
		else {
			extra = TRUE;
		}
		if(txt_result && extra){
			txt_desc = "It was possible to execute the command \"" + command + "\" on the remote host, which produces the following output:\n\n" + txt_result;
			security_message( port: port, data: txt_desc );
			exit( 0 );
		}
	}
}
func http_vuln_check( port, url, pattern, check_header, debug, extra_check, host, cookie, check_nomatch, icase, usecache ){
	var port, url, pattern, check_header, debug, extra_check, host, cookie, check_nomatch, icase, usecache;
	var buf, req, _ec, _nm;
	if(!url){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#url#-#http_vuln_check" );
		return NULL;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_vuln_check" );
		return NULL;
	}
	if(isnull( pattern ) || pattern == ""){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#pattern#-#http_vuln_check" );
		return NULL;
	}
	if(isnull( icase )){
		icase = TRUE;
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
	}
	if( usecache ){
		buf = http_get_cache( item: url, port: port, host: host );
		if(cookie && !isnull( cookie )){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_vuln_check(): Setting nocache to TRUE and passing a cookie isn't supported." );
		}
	}
	else {
		req = http_get( item: url, port: port );
		if(cookie && !isnull( cookie )){
			req = ereg_replace( string: req, pattern: "\r\n\r\n", replace: "\r\nCookie: " + cookie + "\r\n\r\n" );
		}
		buf = http_keepalive_send_recv( port: port, host: host, data: req );
		__ka_last_request[host + "#--#" + port] = req;
	}
	if(isnull( buf ) || buf == "" || !buf){
		return FALSE;
	}
	if(debug){
		display( "\\nContent:\\n", buf, "\\n" );
	}
	if(check_header == TRUE){
		if(!ereg( pattern: "^HTTP/[0-9]\\.[0-9] 200.*", string: buf )){
			return FALSE;
		}
	}
	if(extra_check){
		if(NASLTypeof( extra_check ) != "array"){
			extra_check = make_list( extra_check );
		}
		for _ec in extra_check {
			if(!egrep( pattern: _ec, string: buf, icase: icase )){
				return FALSE;
			}
		}
	}
	if(check_nomatch){
		if(NASLTypeof( check_nomatch ) != "array"){
			check_nomatch = make_list( check_nomatch );
		}
		for _nm in check_nomatch {
			if(egrep( pattern: _nm, string: buf, icase: icase )){
				return FALSE;
			}
		}
	}
	if( egrep( pattern: pattern, string: buf, icase: icase ) ) {
		return buf;
	}
	else {
		return FALSE;
	}
}
func http_ka_recv_buf( port, host, url, bodyonly, nocache ){
	var port, host, url, bodyonly, nocache;
	var res, req;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_ka_recv_buf" );
		return NULL;
	}
	if(!url){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#url#-#http_ka_recv_buf" );
		return NULL;
	}
	if(!host){
		host = http_host_name( dont_add_port: TRUE );
	}
	if(!nocache){
		if(!egrep( pattern: "(\\?|&|#|;|\\[|\\]|=)", string: url )){
			if(bodyonly){
				set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_ka_recv_buf(): nocache set to FALSE but bodyonly set to TRUE, response will contain the body." );
			}
			res = http_get_cache( item: url, port: port, host: host );
			return res;
		}
	}
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, host: host, data: req, bodyonly: bodyonly );
	return res;
}
func http_keepalive_reopen_connection( host, port ){
	var host, port;
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_keepalive_reopen_connection" );
		return NULL;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_keepalive_reopen_connection" );
		return NULL;
	}
	if(__ka_sockets[host + "#--#" + port]){
		http_close_socket( __ka_sockets[host + "#--#" + port] );
	}
	__ka_port = port;
	__ka_sockets[host + "#--#" + port] = http_open_socket( port );
}

