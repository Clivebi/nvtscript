var _http_ua_include_oid;
_http_ua_include_oid = FALSE;
var __http_func_user_agent, __http_is_cgi_scan_disabled, __http_is_kb_caching_disabled;
var _http_debug;
_http_debug = FALSE;
var optimize_test_enabled;
optimize_test_enabled = get_preference( "optimize_test" );
var _http_is_broken_array, _http_no404_string_array, _http_has_generic_xss_array, _http_is_embedded_array;
_http_is_broken_array = make_array();
_http_no404_string_array = make_array();
_http_has_generic_xss_array = make_array();
_http_is_embedded_array = make_array();
func http_get_user_agent( vt_string=nil, dont_add_oid=nil ){
	var vt_string, dont_add_oid;
	var ua_vt_string, default, ua;
	if( vt_string ) {
		ua_vt_string = vt_string;
	}
	else {
		ua_vt_string = "OpenVAS-VT";
	}
	if( defined_func( "vendor_version" ) ) {
		vendor = vendor_version();
	}
	else {
		vendor = NULL;
	}
	if( !isnull( vendor ) && vendor != "" ) {
		default = "Mozilla/5.0 [en] (X11, U; " + vendor + ")";
	}
	else {
		if( OPENVAS_VERSION ) {
			default = "Mozilla/5.0 [en] (X11, U; " + ua_vt_string + " " + OPENVAS_VERSION + ")";
		}
		else {
			default = "Mozilla/5.0 [en] (X11, U; " + ua_vt_string + ")";
		}
	}
	if( !isnull( __http_func_user_agent ) ){
		ua = NASLString( __http_func_user_agent );
	}
	else {
		ua = get_kb_item( "http/user-agent" );
		if( !isnull( ua ) ){
			__http_func_user_agent = NASLString( ua );
		}
		else {
			__http_func_user_agent = default;
			ua = default;
		}
	}
	if(_http_ua_include_oid && !dont_add_oid){
		ua = ereg_replace( string: ua, pattern: "(.+)$", replace: "\\1 (OID:" + get_script_oid() + ")" );
	}
	return ua;
}
func http_headers_split( h ){
	var h;
	var end, array, _item, subarray, ret;
	if(!h){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#h#-#http_headers_split" );
	}
	end = strstr( h, "\r\n\r\n" );
	if(end){
		h -= end;
	}
	array = split( buffer: h, keep: FALSE );
	for _item in array {
		subarray = split( buffer: _item, sep: ":", keep: FALSE );
		ret[tolower( subarray[0] )] = ereg_replace( pattern: "^ *", replace: "", string: subarray[1] );
	}
	return ret;
}
func __hex_value( num ){
	var num;
	if(num == "a"){
		return ( 10 );
	}
	if(num == "b"){
		return ( 11 );
	}
	if(num == "c"){
		return ( 12 );
	}
	if(num == "d"){
		return ( 13 );
	}
	if(num == "e"){
		return ( 14 );
	}
	if(num == "f"){
		return ( 15 );
	}
	return ( int( num ) );
}
func hex2dec( xvalue ){
	var xvalue;
	var l, ret, m, i, n;
	if(!xvalue){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#xvalue#-#hex2dec" );
		return ( 0 );
	}
	xvalue = tolower( xvalue );
	if( ContainsString( xvalue, "\r\n" ) ){
		l = strlen( xvalue ) - 2;
	}
	else {
		if( ContainsString( xvalue, "\n" ) ){
			l = strlen( xvalue ) - 1;
		}
		else {
			l = strlen( xvalue );
		}
	}
	ret = 0;
	m = 1;
	if(l == 0){
		return ( 0 );
	}
	for(;xvalue[l - 1] == " " && l > 0;){
		l--;
	}
	for(i = l;i > 0;i--){
		n = __hex_value( num: xvalue[i - 1] ) * m;
		ret += n;
		m = m * 16;
	}
	return int( ret );
}
func http_get_remote_headers( port, file, ignore_broken ){
	var port, file, ignore_broken;
	var sb, banner, req, soc, body;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_get_remote_headers" );
		return NULL;
	}
	if(!get_port_state( port )){
		return NULL;
	}
	if(!file){
		file = "/";
	}
	sb = strcat( "www/real_banner/", port, file );
	banner = get_kb_item( sb );
	if(banner){
		return banner;
	}
	sb = strcat( "www/banner/", port, file );
	banner = get_kb_item( sb );
	if(banner){
		return banner;
	}
	if(!ignore_broken && http_get_is_marked_broken( port: port, host: "*" )){
		return NULL;
	}
	req = http_get( item: file, port: port );
	soc = http_open_socket( port );
	if(!soc){
		return NULL;
	}
	send( socket: soc, data: req );
	banner = http_recv_headers2( socket: soc );
	http_close_socket( soc );
	if(banner){
		replace_kb_item( name: sb, value: banner );
	}
	return banner;
}
func http_get_port( default, nodefault, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts ){
	var default, nodefault, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts;
	var port;
	if(!default && !nodefault){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#default#-#http_get_port" );
		exit( 0 );
	}
	if(!ignore_cgi_disabled){
		if(http_is_cgi_scan_disabled()){
			if(optimize_test_enabled && ContainsString( optimize_test_enabled, "yes" )){
				set_kb_item( name: "vt_debug_cgi_scanning_disabled/" + get_script_oid(), value: get_script_oid() + "#-#http_get_port" );
			}
			exit( 0 );
		}
	}
	port = get_kb_item( "Services/www" );
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
	if( !dont_use_vhosts && !host ){
		host = http_host_name( dont_add_port: TRUE );
	}
	else {
		if(!host){
			host = "*";
		}
	}
	if(!ignore_broken && http_get_is_marked_broken( port: default, host: host )){
		exit( 0 );
	}
	return default;
}
func http_get_ports( default_port_list, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts ){
	var default_port_list, host, ignore_broken, ignore_unscanned, ignore_cgi_disabled, dont_use_vhosts;
	var final_port_list, check_port_list, default_ports, num_ports, ports, _port;
	final_port_list = make_list();
	check_port_list = make_list();
	default_ports = make_list( 80,
		 443,
		 8008,
		 8080,
		 8088 );
	num_ports = 0;
	if(!ignore_cgi_disabled){
		if(http_is_cgi_scan_disabled()){
			if(optimize_test_enabled && ContainsString( optimize_test_enabled, "yes" )){
				set_kb_item( name: "vt_debug_cgi_scanning_disabled/" + get_script_oid(), value: get_script_oid() + "#-#http_get_ports" );
			}
			return final_port_list;
		}
	}
	ports = get_kb_list( "Services/www" );
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
	if( !dont_use_vhosts && !host ){
		host = http_host_name( dont_add_port: TRUE );
	}
	else {
		if(!host){
			host = "*";
		}
	}
	for _port in check_port_list {
		if(!ignore_unscanned && !get_port_state( _port )){
			continue;
		}
		if(port_is_marked_fragile( port: _port )){
			continue;
		}
		if(!ignore_broken){
			if(http_get_is_marked_broken( port: _port, host: host )){
				continue;
			}
		}
		final_port_list = make_list( final_port_list,
			 _port );
	}
	return final_port_list;
}
func http_is_dead( port, retry ){
	var port, retry;
	var url, req, i, soc, code, h, h2, b;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_is_dead" );
		return NULL;
	}
	if(!retry){
		retry = 2;
	}
	if(retry > 5){
		retry = 5;
	}
	url = strcat( "/OpenVASTest", rand(), ".html" );
	req = http_get( item: url, port: port );
	i = 0;
	soc = http_open_socket( port );
	for(;!soc && i++ < retry;){
		sleep( i );
		soc = http_open_socket( port );
		if(_http_debug){
			display( "DEBUG: i = ", i, "\\n" );
		}
	}
	if(!soc){
		return TRUE;
	}
	send( socket: soc, data: req );
	code = recv_line( socket: soc, length: 1024 );
	if(code){
		h = http_recv_headers2( socket: soc );
		h2 = strcat( code, h );
		b = http_recv_body( socket: soc, headers: h2 );
	}
	http_close_socket( soc );
	if(!code){
		return TRUE;
	}
	if( ereg( pattern: "^HTTP/1\\.[01] +50[234]", string: code ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func http_recv_headers2( socket ){
	var socket;
	var counter, line, buf;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#http_recv_headers2" );
		return NULL;
	}
	for(;TRUE;){
		counter++;
		line = recv_line( socket: socket, length: 4096 );
		buf += line;
		if(line == "\r\n"){
			break;
		}
		if(!strlen( line )){
			break;
		}
		if(strlen( line ) == 1 && IsMatchRegexp( line, "^\x0a$" )){
			break;
		}
		if(counter > 1024){
			break;
		}
	}
	return buf;
}
func http_recv_body( socket, headers, length ){
	var socket, headers, length;
	var h, l, cl, gzip, max, min, body, tmp, x, n;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#http_recv_body" );
		return NULL;
	}
	if( !headers ){
		h = http_recv_headers2( socket: socket );
	}
	else {
		h = headers;
	}
	l = -1;
	if(egrep( pattern: "^Content-Encoding\\s*:\\s*gzip", string: h, icase: TRUE )){
		gzip = TRUE;
	}
	cl = egrep( pattern: "^Content-Length\\s*:\\s*[0-9]+", string: h, icase: TRUE );
	if(cl){
		l = int( ereg_replace( pattern: "Content-Length\\s*:\\s*([0-9]+).*", replace: "\\1", string: cl, icase: TRUE ) );
	}
	max = -1;
	min = -1;
	if(l < 0 && egrep( pattern: "^Transfer-Encoding\\s*:\\s*chunked", string: h, icase: TRUE )){
		body = "";
		for(;1;){
			tmp = recv_line( socket: socket, length: 4096 );
			if( !tmp ) {
				l = 0;
			}
			else {
				l = hex2dec( xvalue: tmp );
			}
			body = strcat( body, recv( socket: socket, length: l, min: l ) );
			recv( socket: socket, length: 2, min: 2 );
			if(l == 0){
				return ( body );
			}
		}
	}
	if(length){
		max = length;
	}
	if(l >= 0){
		min = int( l );
	}
	if(l >= max || min >= max){
		max = l;
	}
	if(max < 0){
		if(_http_debug){
			display( "DEBUG: http_recv_body: bogus or no Content-length field, and no 'length' parameter set! Defaulting to 32 KB\\n" );
		}
		max = 32768;
	}
	if(_http_debug){
		display( "DEBUG: http_recv_body: min=", min, "; max=", max, "\\n" );
	}
	if( min > 0 ){
		x = recv( socket: socket, length: max, min: min );
	}
	else {
		n = recv( socket: socket, min: max, length: max );
		x = n;
		for(;strlen( n ) >= max && max != 0;){
			n = recv( socket: socket, length: max );
			x += n;
			if(strlen( x ) > 1048576){
				if(_http_debug){
					display( "DEBUG: http_recv_body: read stopped after 1 MB!\\n" );
				}
				break;
			}
		}
	}
	if( gzip && x ) {
		return http_gunzip( buf: x, onlybody: FALSE );
	}
	else {
		return ( x );
	}
}
func http_recv( socket, code ){
	var socket, code;
	var h, l, b;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#http_recv" );
		return NULL;
	}
	if( code ){
		h = strcat( code );
		for{
			l = recv_line( socket: socket, length: 2048 );
			h += l;
			
			if( !l || IsMatchRegexp( l, "^[\r\n]+$" ) ){
				break;
			}
		}
		if(!l){
			return h;
		}
	}
	else {
		h = http_recv_headers2( socket: socket );
		if( !h ) {
			return NULL;
		}
		else {
			if(!ereg( pattern: "^HTTP/.* [0-9]*", string: h )){
				return h;
			}
		}
		h = strcat( h, "\r\n" );
	}
	b = http_recv_body( socket: socket, headers: h, length: 0 );
	return strcat( h, b );
}
func http_recv_length( socket, bodylength ){
	var socket, bodylength;
	var h, b;
	if(!socket){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#http_recv_length" );
		return NULL;
	}
	h = http_recv_headers2( socket: socket );
	b = http_recv_body( socket: socket, headers: h, length: bodylength );
	return strcat( h, "\r\n", b );
}
func http_send_recv( port, data ){
	var port, data;
	var oid, s, x, cl, conlen, r, user_agent, oid_str;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_send_recv" );
		return NULL;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_send_recv" );
		return NULL;
	}
	if(strlen( data ) < 8 || !IsMatchRegexp( data, "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL).*HTTP/(1\\.[01]|2)" )){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.900522" && oid != "1.3.6.1.4.1.25623.1.0.10730"){
			set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_send_recv(): Invalid HTTP request (length < 8, invalid HTTP method or missing HTTP/ header) passed in 'data' variable." );
		}
	}
	if(!IsMatchRegexp( data, "^(DELETE|PROPFIND|PUT|GET|HEAD|POST|OPTIONS|REPORT|MKCOL|MOVE|PROPPATCH|COPY|PATCH|CONNECT|TRACE|LOCK|UNLOCK|TRACK|M-POST|CHECKOUT|CHECKIN|UNCHECKOUT|VERSION-CONTROL|BASELINE-CONTROL) (/|\\.+/|https?:|\\*).* HTTP" )){
		oid = get_script_oid();
		if(oid != "1.3.6.1.4.1.25623.1.0.103293" && oid != "1.3.6.1.4.1.25623.1.0.17230" && oid != "1.3.6.1.4.1.25623.1.0.900522" && oid != "1.3.6.1.4.1.25623.1.0.10730"){
			set_kb_item( name: "vt_debug_misc/" + oid, value: oid + "#-#http_send_recv(): URL/URI of the HTTP request passed in 'data' variable doesn't start with one of the following: '/, ./, http, *'." );
		}
	}
	if(ContainsString( data, " HTTP/1.1" ) && !egrep( pattern: "^User-Agent:.+", string: data, icase: TRUE )){
		data = ereg_replace( string: data, pattern: "\r\n\r\n", replace: "\r\nUser-Agent: " + http_get_user_agent() + "\r\n\r\n" );
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_send_recv(): Using a HTTP/1.1 request without a 'User-Agent:' header passed in 'data' variable. Adding it automatically to the request." );
	}
	if(_http_ua_include_oid && user_agent = egrep( pattern: "^User-Agent:.+", string: data, icase: TRUE )){
		user_agent = chomp( user_agent );
		oid_str = "(OID:" + get_script_oid() + ")";
		if(!ContainsString( user_agent, oid_str )){
			data = str_replace( string: data, find: user_agent, replace: user_agent + " " + oid_str );
		}
	}
	if(_http_debug){
		display( "DEBUG: http_send_recv( port: ", port, ", data: ", data, " )\\n" );
	}
	s = http_open_socket( port );
	if(!s){
		return;
	}
	send( socket: s, data: data );
	for(;x = http_recv( socket: s );){
		if(egrep( pattern: "^Content-Length\\s*:", string: x, icase: TRUE ) && !ContainsString( x, "206 Partial" )){
			cl = eregmatch( pattern: "Content-Length\\s*:\\s*([0-9]+)", string: x, icase: TRUE );
			if(!isnull( cl[1] )){
				conlen = int( cl[1] );
			}
		}
		r += x;
		if(( conlen && conlen > 0 ) && strlen( r ) >= conlen){
			break;
		}
	}
	http_close_socket( s );
	if( egrep( pattern: "^Content-Encoding\\s*:\\s*gzip", string: r, icase: TRUE ) ) {
		return http_gunzip( buf: r );
	}
	else {
		return r;
	}
}
func http_cgi_dirs( port, host ){
	var port, host;
	var kb, usercgis;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_cgi_dirs" );
	}
	if(http_is_cgi_scan_disabled()){
		if(optimize_test_enabled && ContainsString( optimize_test_enabled, "yes" )){
			set_kb_item( name: "vt_debug_cgi_scanning_disabled/" + get_script_oid(), value: get_script_oid() + "#-#http_cgi_dirs()" );
		}
		exit( 0 );
	}
	if( port && host ){
		kb = get_kb_list( "www/" + host + "/" + port + "/content/directories" );
	}
	else {
		if( port && !host ){
			kb = get_kb_list( "www/*/" + port + "/content/directories" );
		}
		else {
			if( !port && host ){
				kb = get_kb_list( "www/" + host + "/*/content/directories" );
			}
			else {
				kb = get_kb_list( "www/*/*/content/directories" );
			}
		}
	}
	usercgis = get_kb_list( "/user/cgis" );
	if(isnull( usercgis )){
		usercgis = "/";
	}
	if( isnull( kb ) ){
		kb = make_list( usercgis,
			 "/" );
	}
	else {
		kb = make_list( usercgis,
			 kb,
			 "/" );
	}
	return ( nasl_make_list_unique( kb ) );
}
func http_can_host_php( port ){
	var port;
	var key, can_host, files, banner, can_host_pattern, cant_host_pattern;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_can_host_php" );
		return NULL;
	}
	key = "www/" + port + "/can_host_php";
	if(can_host = get_kb_item( key )){
		if( can_host == "yes" ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	if(get_kb_item( "www/" + port + "/PHP" )){
		set_kb_item( name: key, value: "yes" );
		return TRUE;
	}
	files = http_get_kb_file_extensions( port: port, host: "*", ext: "php*" );
	if(!isnull( files )){
		set_kb_item( name: key, value: "yes" );
		return TRUE;
	}
	banner = http_get_remote_headers( port: port );
	if(!banner){
		set_kb_item( name: key, value: "no" );
		return FALSE;
	}
	if(egrep( pattern: "((powered|server).*php|set-cookie\\s*:.*phpsessid|content-type\\s*:\\s*application/x-appweb-php|daap-server\\s*:\\s*ampache)", string: banner, icase: TRUE )){
		set_kb_item( name: key, value: "yes" );
		return TRUE;
	}
	can_host_pattern = "(apache|nginx|thttpd|aolserver|pi3web|zeus|iis|icewarp|lighttpd|";
	can_host_pattern += "hiawatha|litespeed|caddy|panweb|embedthis-http|embedthis-appweb|mbedthis-appweb|";
	can_host_pattern += "Oracle-iPlanet-Web-Server|Sun-Java-System-Web-Server|Sun-ONE-Web-Server)";
	if(egrep( pattern: "^Server\\s*:.*" + can_host_pattern, string: banner, icase: TRUE )){
		set_kb_item( name: key, value: "yes" );
		return TRUE;
	}
	cant_host_pattern = "(user-agent\\s*:\\s*loolwsd wopi|x-powered-by\\s*:\\s*express|";
	cant_host_pattern += "^Server\\s*:.*(sdk for upnp|miniupnp|NessusWWW|MiniServ|pve-api-daemon|ZNC|(microsoft-)?cassini)|^DAAP-Server\\s*:)";
	if(egrep( pattern: cant_host_pattern, string: banner, icase: TRUE )){
		set_kb_item( name: key, value: "no" );
		return FALSE;
	}
	set_kb_item( name: key, value: "yes" );
	return TRUE;
}
func http_can_host_asp( port ){
	var port;
	var key, can_host, files, banner, can_host_pattern, cant_host_pattern;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_can_host_asp" );
		return NULL;
	}
	key = "www/" + port + "/can_host_asp";
	if(can_host = get_kb_item( key )){
		if( can_host == "yes" ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	files = http_get_kb_file_extensions( port: port, host: "*", ext: "asp*" );
	if(!isnull( files )){
		set_kb_item( name: key, value: "yes" );
		return TRUE;
	}
	banner = http_get_remote_headers( port: port );
	if(!banner){
		set_kb_item( name: key, value: "no" );
		return FALSE;
	}
	if(egrep( pattern: "((powered|server).*asp|set-cookie\\s*:.*(asp\\.net_sessionid|aspsessionid)|x-aspnet(mvc)?-version|x-owa-version\\s*:)", string: banner, icase: TRUE )){
		set_kb_item( name: key, value: "yes" );
		return TRUE;
	}
	can_host_pattern = "(iis|goahead-webs|(microsoft-)?cassini|microsoft-wince)";
	if(egrep( pattern: "^Server\\s*:.*" + can_host_pattern, string: banner, icase: TRUE )){
		set_kb_item( name: key, value: "yes" );
		return TRUE;
	}
	cant_host_pattern = "(user-agent\\s*:\\s*loolwsd wopi|x-powered-by\\s*:\\s*express|";
	cant_host_pattern += "^Server\\s*:.*(sdk for upnp|miniupnp|NessusWWW|MiniServ|Apache|nginx|";
	cant_host_pattern += "pve-api-daemon|ZNC|lighttpd|Oracle-iPlanet-Web-Server|";
	cant_host_pattern += "Sun-Java-System-Web-Server|Sun-ONE-Web-Server)|^DAAP-Server\\s*:)";
	if(egrep( pattern: cant_host_pattern, string: banner, icase: TRUE )){
		set_kb_item( name: key, value: "no" );
		return FALSE;
	}
	set_kb_item( name: key, value: "yes" );
	return TRUE;
}
func http_gunzip( buf, onlybody ){
	var buf, onlybody;
	var lines, _line, sep, header, body, h;
	if(!buf){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#buf#-#http_gunzip" );
		return FALSE;
	}
	if(ContainsString( buf, "##**##UNZIPPED##**##" )){
		return buf;
	}
	if(!egrep( pattern: "^Content-Encoding\\s*:\\s*gzip", string: buf, icase: TRUE ) && !onlybody){
		return buf;
	}
	if( !onlybody ){
		lines = split( buffer: buf, keep: FALSE );
		for _line in lines {
			if(!sep && !IsMatchRegexp( _line, "^$" )){
				header += _line + "\n";
			}
			if(IsMatchRegexp( _line, "^$" ) && !body){
				sep = TRUE;
				continue;
			}
			if(sep){
				body += _line + "\n";
			}
		}
	}
	else {
		body = buf;
	}
	if(!body){
		return buf;
	}
	if(body = gunzip( data: body )){
		if(onlybody){
			return body + "\n\n\n##**##UNZIPPED##**##";
		}
		h = ereg_replace( string: header, pattern: "(content-encoding\\s*:\\s*[^\r\n]+[\r\n]+)", replace: "", icase: TRUE );
		return ( h + "\r\n\r\n" + body + "\n\n\n##**##UNZIPPED##**##" );
	}
	return buf;
}
func http_host_name( port, use_ip, dont_add_port ){
	var port, use_ip, dont_add_port;
	var host;
	if( use_ip ){
		host = get_host_ip();
	}
	else {
		host = get_host_name();
	}
	if(dont_add_port){
		return host;
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_host_name" );
	}
	if(port){
		if(port != 80 && port != 443){
			host += ":" + port;
		}
	}
	return host;
}
func http_extract_location_from_redirect( port, data, debug, dir_only, current_dir ){
	var port, data, debug, dir_only, current_dir;
	var host, ip, location_header, location_target, location_host, _location, return_location;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_extract_location_from_redirect" );
		return;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_extract_location_from_redirect" );
		return;
	}
	if(!current_dir){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_extract_location_from_redirect(): No 'current_dir' passed, assuming '/'." );
		current_dir = "/";
	}
	passed_dir = current_dir;
	if(IsMatchRegexp( current_dir, "/$" ) && current_dir != "/"){
		current_dir = ereg_replace( string: current_dir, pattern: "/$", replace: "" );
	}
	location_header = egrep( string: data, pattern: "^Location\\s*:\\s*[^\\r\\n]+", icase: TRUE );
	if(!location_header){
		if(debug || _http_debug){
			display( "DEBUG: Empty or missing Location header." );
		}
		return;
	}
	location_header = chomp( location_header );
	if(IsMatchRegexp( location_header, "^Location\\s*:$" )){
		if(debug || _http_debug){
			display( "DEBUG: Empty Location header received: \"" + location_header + "\"" );
		}
		return;
	}
	if(debug || _http_debug){
		display( "DEBUG: Location header is: \"" + location_header + "\"" );
	}
	location_target = ereg_replace( string: location_header, pattern: "Location\\s*:\\s*(.+)$", replace: "\\1", icase: TRUE );
	if(debug || _http_debug){
		display( "DEBUG: Location header after removing the \"Location:\" prefix is: \"" + location_target + "\"" );
	}
	if( IsMatchRegexp( location_target, "^(https?:)?//" ) ){
		location_host = ereg_replace( string: location_target, pattern: "^(https?:)?//([^/]*)/.*", replace: "\\2", icase: TRUE );
		if(debug || _http_debug){
			display( "DEBUG: Location header is pointing to host/ip: \"" + location_host + "\"" );
		}
		ip = get_host_ip();
		host = http_host_name( port: port );
		if( ContainsString( location_host, host ) || ContainsString( location_host, ip ) ){
			_location = ereg_replace( string: location_target, pattern: "^(https?:)?//[^/]*/([^?]*)", replace: "/\\2", icase: TRUE );
			if( dir_only ){
				if( IsMatchRegexp( _location, "/$" ) ){
					return_location = _location;
				}
				else {
					if( IsMatchRegexp( _location, "([^/]*)/[^/]+\\.[^/]+" ) ){
						_location = eregmatch( string: _location, pattern: "/(.*[^/]*)/[^/]+\\.[^/]+" );
						if( isnull( _location[1] ) ) {
							return_location = "/";
						}
						else {
							return_location = "/" + _location[1];
						}
					}
					else {
						return_location = _location;
					}
				}
				if(return_location != "/"){
					return_location = ereg_replace( string: return_location, pattern: "/$", replace: "" );
				}
				if(debug || _http_debug){
					display( "DEBUG: Location header is pointing to \"" + location_target + "\" on the same host/ip. dir_only parameter is set to TRUE, returning the \"" + return_location + "\" part of the location." );
				}
			}
			else {
				return_location = _location;
				if(debug || _http_debug){
					display( "DEBUG: Location header is pointing to \"" + location_target + "\" on the same host/ip. Returning the \"" + return_location + "\" part of the location." );
				}
			}
			return return_location;
		}
		else {
			if(debug || _http_debug){
				display( "DEBUG: Location header is pointing to \"" + location_target + "\" NOT on the same host/ip. NOT returning this location." );
			}
			return;
		}
	}
	else {
		if( !IsMatchRegexp( location_target, "^/" ) && !IsMatchRegexp( location_target, "^\\.+/" ) ){
			return_location = current_dir;
			if(current_dir != "/"){
				return_location += "/";
			}
			if( dir_only ){
				if( IsMatchRegexp( location_target, "/$" ) ){
					return_location += location_target;
				}
				else {
					if( IsMatchRegexp( location_target, "([^/]*)/[^/]+\\.[^/]+" ) ){
						_location = eregmatch( string: location_target, pattern: "(.*[^/]*)/[^/]+\\.[^/]+" );
						if(!isnull( _location[1] )){
							return_location += _location[1];
						}
					}
					else {
						if(!ContainsString( location_target, "." )){
							return_location += location_target;
						}
					}
				}
				if(return_location != "/"){
					return_location = ereg_replace( string: return_location, pattern: "/$", replace: "" );
				}
				if(debug || _http_debug){
					display( "DEBUG: Location header is pointing to \"" + location_target + "\" (a relative path to the passed current dir \"" + passed_dir + "\") on the same host/ip. dir_only parameter is set to TRUE, returning \"" + return_location + "\" as the location." );
				}
			}
			else {
				return_location += location_target;
				if(debug || _http_debug){
					display( "DEBUG: Location header is pointing to \"" + location_target + "\" (a relative path to the passed current dir \"" + passed_dir + "\") on the same host/ip. Returning \"" + return_location + "\" as the location." );
				}
			}
			return return_location;
		}
		else {
			if( dir_only ){
				if( IsMatchRegexp( location_target, "/$" ) ){
					return_location = location_target;
				}
				else {
					if( IsMatchRegexp( location_target, "([^/]*)/[^/]+\\.[^/]+" ) ){
						_location = eregmatch( string: location_target, pattern: "/(.*[^/]*)/[^/]+\\.[^/]+" );
						if( isnull( _location[1] ) ) {
							return_location = "/";
						}
						else {
							return_location = "/" + _location[1];
						}
					}
					else {
						return_location = location_target;
					}
				}
				if(return_location != "/"){
					return_location = ereg_replace( string: return_location, pattern: "/$", replace: "" );
				}
				if(debug || _http_debug){
					display( "DEBUG: Location header is pointing to \"" + location_target + "\" on the same host/ip. dir_only parameter is set to TRUE, returning \"" + return_location + "\" as the location." );
				}
			}
			else {
				return_location = location_target;
				if(debug || _http_debug){
					display( "DEBUG: Location header is pointing to \"" + return_location + "\" on the same host/ip. Returning this location." );
				}
			}
			return return_location;
		}
	}
}
func http_get_cookie_from_header( buf, pattern ){
	var buf, pattern;
	var match;
	if(!buf){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#buf#-#http_get_cookie_from_header" );
		return;
	}
	if(!pattern){
		pattern = "Set-Cookie\\s*:\\s*([^\r\n]+)";
	}
	if( match = eregmatch( pattern: pattern, string: buf ) ) {
		return match[max_index( match ) - 1];
	}
	else {
		return;
	}
}
func http_create_exploit_req( cgiArray, ex ){
	var cgiArray, ex;
	var urls, pseudocount, _rrayval, tmpf, data, param, z, url, i;
	urls = make_array();
	pseudocount = 0;
	for _rrayval in cgiArray {
		if( pseudocount >= 2 ){
			if( ContainsString( _rrayval, "]" ) ){
				pseudocount--;
				tmpf = ereg_replace( pattern: "\\[|\\]", string: _rrayval, replace: "" );
				data[pseudocount] = tmpf;
			}
			else {
				param[pseudocount] = _rrayval;
			}
		}
		else {
			param[pseudocount] = _rrayval;
		}
		pseudocount++;
	}
	for(z = 2;z < max_index( param );z++){
		url = NASLString( param[0], "?" );
		for(i = 2;i < max_index( param );i++){
			if( z == i ){
				url += param[i] + "=" + ex;
			}
			else {
				if( data[i] ){
					url += param[i] + "=" + data[i];
				}
				else {
					url += param[i] + "=";
				}
			}
			if(param[i + 1]){
				url += "&";
			}
		}
		urls = make_list( urls,
			 url + "&" );
	}
	return urls;
}
func http_extract_basic_auth( data ){
	var data;
	var infos, header, realm;
	infos = make_array( "basic_auth", FALSE, "realm", "Undefined/Unknown" );
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_extract_basic_auth" );
		return infos;
	}
	if(!header = egrep( pattern: "^WWW-Authenticate\\s*:\\s*Basic", string: data, icase: TRUE )){
		return infos;
	}
	infos["basic_auth"] = TRUE;
	realm = eregmatch( pattern: "realm=(.*)", string: header, icase: TRUE );
	if(realm[1]){
		infos["realm"] = chomp( realm[1] );
	}
	return infos;
}
func http_get_is_marked_broken( port, host ){
	var port, host;
	var marked_broken_list, marked_broken, _mb;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_get_is_marked_broken" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_get_is_marked_broken" );
		host = http_host_name( dont_add_port: TRUE );
	}
	if(!isnull( _http_is_broken_array[host + port] )){
		if( _http_is_broken_array[host + port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	if( host == "*" ){
		marked_broken_list = get_kb_list( "www/*/" + port + "/is_broken" );
		if( !marked_broken_list || NASLTypeof( marked_broken_list ) != "array" ){
			marked_broken = FALSE;
		}
		else {
			for _mb in marked_broken_list {
				if(_mb){
					marked_broken = TRUE;
					break;
				}
			}
		}
	}
	else {
		marked_broken = get_kb_item( "www/" + host + "/" + port + "/is_broken" );
	}
	if( marked_broken ){
		_http_is_broken_array[host + port] = TRUE;
	}
	else {
		_http_is_broken_array[host + port] = FALSE;
		marked_broken = FALSE;
	}
	return marked_broken;
}
func http_set_is_marked_broken( port, host, reason ){
	var port, host, reason;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_set_is_marked_broken" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_set_is_marked_broken" );
		return NULL;
	}
	if(strlen( reason ) > 0){
		set_kb_item( name: "www/" + host + "/" + port + "/broken/reason", value: reason );
	}
	set_kb_item( name: "www/" + host + "/" + port + "/is_broken", value: TRUE );
	_http_is_broken_array[host + port] = TRUE;
	return TRUE;
}
func http_get_kb_file_extensions( port, host, ext ){
	var port, host, ext;
	var list, _item;
	if(!port){
		port = "*";
	}
	if(!host){
		host = "*";
	}
	if(!ext){
		ext = "*";
	}
	list = get_kb_list( "www/" + host + "/" + port + "/content/extensions/" + ext );
	if(!list || NASLTypeof( list ) != "array"){
		return NULL;
	}
	if(max_index( list ) == 0){
		for _item in list {
			return list;
		}
		return NULL;
	}
	return list;
}
func http_get_kb_auth_required( port, host ){
	var port, host;
	var list, _item;
	if(!port){
		port = "*";
	}
	if(!host){
		host = "*";
	}
	list = get_kb_list( "www/" + host + "/" + port + "/content/auth_required" );
	if(!list || NASLTypeof( list ) != "array"){
		return NULL;
	}
	if(max_index( list ) == 0){
		for _item in list {
			return list;
		}
		return NULL;
	}
	return list;
}
func http_get_kb_cgis( port, host ){
	var port, host;
	var list, _item;
	if(!port){
		port = "*";
	}
	if(!host){
		host = "*";
	}
	list = get_kb_list( "www/" + host + "/" + port + "/content/cgis/plain_cgis" );
	if(!list || NASLTypeof( list ) != "array"){
		return NULL;
	}
	if(max_index( list ) == 0){
		for _item in list {
			return list;
		}
		return NULL;
	}
	return list;
}
func http_get_kb_cgis_full( port, host ){
	var port, host;
	var list, _item;
	if(!port){
		port = "*";
	}
	if(!host){
		host = "*";
	}
	list = get_kb_list( "www/" + host + "/" + port + "/content/cgis/full_cgis" );
	if(!list || NASLTypeof( list ) != "array"){
		return NULL;
	}
	if(max_index( list ) == 0){
		for _item in list {
			return list;
		}
		return NULL;
	}
	return list;
}
func http_get_no404_string( port, host ){
	var port, host;
	var no404_string, no404_string_list, _no404_string;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_get_no404_string" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_get_no404_string" );
		host = http_host_name( dont_add_port: TRUE );
	}
	if(!isnull( _http_no404_string_array[host + port] )){
		if( no404_string = _http_no404_string_array[host + port] ) {
			return no404_string;
		}
		else {
			return FALSE;
		}
	}
	if( host == "*" ){
		no404_string_list = get_kb_list( "www/*/" + port + "/no404_string" );
		if( !no404_string_list || NASLTypeof( no404_string_list ) != "array" ){
			no404_string = FALSE;
		}
		else {
			for _no404_string in no404_string_list {
				if(_no404_string && strlen( _no404_string ) > 0){
					no404_string = _no404_string;
					break;
				}
			}
		}
	}
	else {
		no404_string = get_kb_item( "www/" + host + "/" + port + "/no404_string" );
	}
	if( no404_string && strlen( no404_string ) > 0 ) {
		_http_no404_string_array[host + port] = no404_string;
	}
	else {
		_http_no404_string_array[host + port] = FALSE;
	}
	return no404_string;
}
func http_set_no404_string( port, host, string ){
	var port, host, string;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_set_no404_string" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_set_no404_string" );
		return NULL;
	}
	if(!string){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#string#-#http_set_no404_string" );
		return NULL;
	}
	set_kb_item( name: "www/" + host + "/" + port + "/no404_string", value: string );
	return TRUE;
}
func http_data_has_40x( port, host, data ){
	var port, host, data;
	var no404;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_data_has_40x" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_data_has_40x" );
		return NULL;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_data_has_40x" );
		return NULL;
	}
	if(!ereg( string: data, pattern: "^HTTP/1\\.[01] +[0-9]+" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_data_has_40x(): No data containing a valid HTTP status code passed in data variable." );
		return NULL;
	}
	if(ereg( string: data, pattern: "^HTTP/1\\.[01] +40[0-9]" )){
		return TRUE;
	}
	no404 = http_get_no404_string( port: port, host: host );
	if( no404 && ContainsString( data, no404 ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func http_data_has_200( port, host, data ){
	var port, host, data;
	var no404;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_data_has_200" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_data_has_200" );
		return NULL;
	}
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_data_has_200" );
		return NULL;
	}
	if(!ereg( string: data, pattern: "^HTTP/1\\.[01] +[0-9]+" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_data_has_200(): No data containing a valid HTTP status code passed in data variable." );
		return NULL;
	}
	if(ereg( string: data, pattern: "^HTTP/1\\.[01] +200" )){
		no404 = http_get_no404_string( port: port, host: host );
		if(!no404 || !ContainsString( data, no404 )){
			return TRUE;
		}
	}
	return FALSE;
}
func http_report_vuln_url( port, url, url_only ){
	var port, url, url_only;
	var proto, host, report;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_report_vuln_url" );
		return NULL;
	}
	if(!url){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#url#-#http_report_vuln_url" );
		return NULL;
	}
	proto = "http";
	if(get_port_transport( port ) > ENCAPS_IP){
		proto = "https";
	}
	host = http_host_name( port: port );
	if( url_only ){
		report = proto + "://" + host + url;
	}
	else {
		report = "Vulnerable URL: " + proto + "://" + host + url;
	}
	return report;
}
func http_post_put_req( port, url, data, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url, method ){
	var port, url, data, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url, method;
	var x_header, len, vtstrings, x_scanner_string, host, req, _header;
	if(!isnull( add_headers )){
		if(NASLTypeof( add_headers ) != "array"){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#add_headers_no-array#-#http_post_put_req" );
			return;
		}
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_post_put_req" );
		return;
	}
	if(method && !IsMatchRegexp( method, "^(POST|PUT)$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_post_put_req(): Unsupported method '" + method + "' passed to the 'method' parameter (Currently supported: POST, PUT). Falling back to the default 'POST'." );
		method = "POST";
	}
	if(!url){
		url = "/";
	}
	x_header = FALSE;
	if(data){
		len = strlen( data );
	}
	if(!accept_header){
		accept_header = "*/*";
	}
	if(!accept_encoding){
		accept_encoding = "identity";
	}
	if( !user_agent ){
		user_agent = http_get_user_agent();
	}
	else {
		if(!dont_add_xscanner){
			x_header = TRUE;
			vtstrings = get_vt_strings();
			if( OPENVAS_VERSION ) {
				x_scanner_string = "X-Scanner: " + vtstrings["default"] + " " + OPENVAS_VERSION;
			}
			else {
				x_scanner_string = "X-Scanner: " + vtstrings["default"];
			}
		}
	}
	if( host_header_use_ip ) {
		host = http_host_name( port: port, use_ip: TRUE );
	}
	else {
		host = http_host_name( port: port );
	}
	if( method && IsMatchRegexp( method, "^(POST|PUT)$" ) ) {
		method = toupper( method );
	}
	else {
		method = "POST";
	}
	req = method + " " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Pragma: no-cache\r\n" + "User-Agent: " + user_agent + "\r\n" + "Accept-Language: en\r\n" + "Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1\r\n" + "Accept: " + accept_header + "\r\n" + "Accept-Encoding: " + accept_encoding + "\r\n";
	if(referer_url){
		proto = "http";
		if(get_port_transport( port ) > ENCAPS_IP){
			proto = "https";
		}
		req += "Referer: " + proto + "://" + host + referer_url + "\r\n";
	}
	if(data){
		req += "Content-Length: " + len + "\r\n";
	}
	if(x_header){
		req += x_scanner_string + "\r\n";
	}
	if(!isnull( add_headers )){
		for _header in keys( add_headers ) {
			req += _header + ": " + add_headers[_header] + "\r\n";
		}
	}
	req += "\r\n";
	if(data){
		req += data;
	}
	return req;
}
func http_get_req( port, url, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url ){
	var port, url, add_headers, accept_header, accept_encoding, user_agent, host_header_use_ip, dont_add_xscanner, referer_url;
	var x_header, vtstrings, x_scanner_string, host, req, _header;
	if(!isnull( add_headers )){
		if(NASLTypeof( add_headers ) != "array"){
			set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#add_headers_no-array#-#http_get_req" );
			return;
		}
	}
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_get_req" );
		return;
	}
	if(!url){
		url = "/";
	}
	x_header = FALSE;
	if(!accept_header){
		accept_header = "image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*";
	}
	if( !user_agent ){
		user_agent = http_get_user_agent();
	}
	else {
		if(!dont_add_xscanner){
			x_header = TRUE;
			vtstrings = get_vt_strings();
			if( OPENVAS_VERSION ) {
				x_scanner_string = "X-Scanner: " + vtstrings["default"] + " " + OPENVAS_VERSION;
			}
			else {
				x_scanner_string = "X-Scanner: " + vtstrings["default"];
			}
		}
	}
	if( host_header_use_ip ) {
		host = http_host_name( port: port, use_ip: TRUE );
	}
	else {
		host = http_host_name( port: port );
	}
	req = "GET " + url + " HTTP/1.1\r\n" + "Connection: Close\r\n" + "Host: " + host + "\r\n" + "Pragma: no-cache\r\n" + "Cache-Control: no-cache\r\n" + "User-Agent: " + user_agent + "\r\n" + "Accept: " + accept_header + "\r\n" + "Accept-Language: en\r\n" + "Accept-Charset: iso-8859-1,*,utf-8\r\n";
	if(referer_url){
		proto = "http";
		if(get_port_transport( port ) > ENCAPS_IP){
			proto = "https";
		}
		req += "Referer: " + proto + "://" + host + referer_url + "\r\n";
	}
	if(x_header){
		req += x_scanner_string + "\r\n";
	}
	if(accept_encoding){
		req += "Accept-Encoding: " + accept_encoding + "\r\n";
	}
	if(!isnull( add_headers )){
		for _header in keys( add_headers ) {
			req += _header + ": " + add_headers[_header] + "\r\n";
		}
	}
	req += "\r\n";
	return req;
}
func http_get_has_generic_xss( port, host ){
	var port, host;
	var generic_xss_list, generic_xss, _gxss;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_get_has_generic_xss" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_get_has_generic_xss" );
		host = http_host_name( dont_add_port: TRUE );
	}
	if(!isnull( _http_has_generic_xss_array[host + port] )){
		if( _http_has_generic_xss_array[host + port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	if( host == "*" ){
		generic_xss_list = get_kb_list( "www/*/" + port + "/generic_xss" );
		if( !generic_xss_list || NASLTypeof( generic_xss_list ) != "array" ){
			generic_xss = FALSE;
		}
		else {
			for _gxss in generic_xss_list {
				if(_gxss){
					generic_xss = TRUE;
					break;
				}
			}
		}
	}
	else {
		generic_xss = get_kb_item( "www/" + host + "/" + port + "/generic_xss" );
	}
	if( generic_xss ) {
		_http_has_generic_xss_array[host + port] = TRUE;
	}
	else {
		_http_has_generic_xss_array[host + port] = FALSE;
	}
	return generic_xss;
}
func http_set_has_generic_xss( port, host ){
	var port, host;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_set_has_generic_xss" );
		return NULL;
	}
	if(!host){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#host#-#http_set_has_generic_xss" );
		return NULL;
	}
	set_kb_item( name: "www/" + host + "/" + port + "/generic_xss", value: TRUE );
	return TRUE;
}
func http_is_cgi_scan_disabled(  ){
	var is_cgi_scan_disabled;
	if( !isnull( __http_is_cgi_scan_disabled ) ){
		is_cgi_scan_disabled = __http_is_cgi_scan_disabled;
	}
	else {
		is_cgi_scan_disabled = get_kb_item( "Settings/disable_cgi_scanning" );
		if( is_cgi_scan_disabled ) {
			__http_is_cgi_scan_disabled = TRUE;
		}
		else {
			__http_is_cgi_scan_disabled = FALSE;
		}
		is_cgi_scan_disabled = __http_is_cgi_scan_disabled;
	}
	return is_cgi_scan_disabled;
}
func http_get_is_marked_embedded( port ){
	var port;
	var marked_embedded_list, marked_embedded;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_get_is_marked_embedded" );
		return NULL;
	}
	if(!isnull( _http_is_embedded_array[port] )){
		if( _http_is_embedded_array[port] ) {
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	marked_embedded = get_kb_item( "www/" + port + "/is_embedded" );
	if( marked_embedded ){
		_http_is_embedded_array[port] = TRUE;
	}
	else {
		_http_is_embedded_array[port] = FALSE;
		marked_embedded = FALSE;
	}
	return marked_embedded;
}
func http_set_is_marked_embedded( port ){
	var port;
	if(!port){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#http_set_is_marked_embedded" );
		return NULL;
	}
	set_kb_item( name: "www/" + port + "/is_embedded", value: TRUE );
	_http_is_embedded_array[port] = TRUE;
	return TRUE;
}
func http_extract_body_from_response( data ){
	var data;
	var pattern, split;
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_extract_body_from_response" );
		return NULL;
	}
	if(!IsMatchRegexp( data, "^HTTP/1\\.[01] [0-9]{3}" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_extract_body_from_response(): Invalid data not containing HTTP headers passed." );
		return data;
	}
	pattern = "\r\n\r\n#######header#######body#######split#######";
	data = str_replace( string: data, find: "\r\n\r\n", replace: pattern, count: 1 );
	if(!ContainsString( data, pattern )){
		return data;
	}
	split = split( buffer: data, sep: pattern, keep: FALSE );
	if(max_index( split ) != 2){
		return data;
	}
	return split[1];
}
func http_extract_headers_from_response( data ){
	var data;
	var pattern, split;
	if(!data){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#http_extract_headers_from_response" );
		return NULL;
	}
	if(!IsMatchRegexp( data, "^HTTP/1\\.[01] [0-9]{3}" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#http_extract_headers_from_response(): Invalid data not containing HTTP headers passed." );
		return data;
	}
	pattern = "\r\n\r\n#######header#######body#######split#######";
	data = str_replace( string: data, find: "\r\n\r\n", replace: pattern, count: 1 );
	if(!ContainsString( data, pattern )){
		return data;
	}
	split = split( buffer: data, sep: pattern, keep: FALSE );
	if(max_index( split ) != 2){
		return data;
	}
	return split[0];
}
func http_is_kb_caching_disabled(  ){
	var is_kb_caching_disabled;
	if( !isnull( __http_is_kb_caching_disabled ) ){
		is_kb_caching_disabled = __http_is_kb_caching_disabled;
	}
	else {
		is_kb_caching_disabled = get_kb_item( "global_settings/disable_http_kb_caching" );
		if( is_kb_caching_disabled ) {
			__http_is_kb_caching_disabled = TRUE;
		}
		else {
			__http_is_kb_caching_disabled = FALSE;
		}
		is_kb_caching_disabled = __http_is_kb_caching_disabled;
	}
	return is_kb_caching_disabled;
}

