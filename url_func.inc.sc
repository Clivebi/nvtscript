var HEX_LOWERCASE, HEX_UPPERCASE;
HEX_LOWERCASE = 1;
HEX_UPPERCASE = 2;
var recur_candidates;
recur_candidates = make_array();
func urlencode( str, uppercase, unreserved ){
	var i, j, str, uppercase, estr="", char_set, num_set, specl_char_set, unreserv_chars, unreserved, flag;
	if(!str){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#str#-#urlencode" );
	}
	char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	num_set = "0123456789";
	specl_char_set = "_-.!~*'()";
	unreserv_chars = char_set + num_set + specl_char_set;
	if(unreserved != NULL){
		unreserv_chars = unreserv_chars + unreserved;
	}
	for(i = 0;i < strlen( str );i++){
		flag = "non_word";
		for(j = 0;j < strlen( unreserv_chars );j++){
			if(str[i] == unreserv_chars[j]){
				flag = "word";
				break;
			}
		}
		if( flag == "non_word" ){
			if( uppercase ) {
				estr = estr + "%" + toupper( hexstr( str[i] ) );
			}
			else {
				estr = estr + "%" + hexstr( str[i] );
			}
		}
		else {
			estr = estr + str[i];
		}
	}
	return ( estr );
}
func urldecode( estr ){
	var estr, dstr, i;
	if(!estr){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#estr#-#urldecode" );
	}
	for(i = 0;i < strlen( estr );i++){
		if( estr[i] == "%" ){
			dstr = dstr + hex2raw( s: tolower( estr[i + 1] + estr[i + 2] ) );
			i = i + 2;
		}
		else {
			if( estr[i] == "+" ){
				dstr = dstr + " ";
				i = i + 1;
			}
			else {
				dstr = dstr + estr[i];
			}
		}
	}
	dstr = ereg_replace( string: dstr, pattern: "<!--(.|\\n)*-->", replace: "", icase: TRUE );
	return ( dstr );
}
func clean_url( url ){
	var url;
	var _search;
	if(!url){
		return url;
	}
	for _search in make_list( "'",
		 " ",
		 "\"" ) {
		if(!isnull( url )){
			url = str_replace( string: url, find: _search, replace: "");
		}
	}
	return url;
}
func canonical_url( url, current, port, host, debug, webmirror_called ){
	var url, current, port, host, debug, webmirror_called;
	var location, num_dots, i;
	url = clean_url( url: url );
	if(debug > 1){
		display( "***** canonical '", url, "' (current:", current, ")" );
	}
	if(strlen( url ) == 0){
		return NULL;
	}
	if(url[0] == "#"){
		return NULL;
	}
	if(url == "./" || url == "." || IsMatchRegexp( url, "^\\./\\?" )){
		return make_list( current,
			 url );
	}
	if(check_recursion_candidates( url: url, current: current, port: port, host: host, debug: debug, webmirror_called: webmirror_called )){
		return NULL;
	}
	if(debug > 2){
		display( "**** canonical(again) ", url );
	}
	if( ereg( pattern: "[a-z]*:", string: url, icase: TRUE ) ){
		if( ereg( pattern: "^http://", string: url, icase: TRUE ) ){
			location = ereg_replace( string: url, pattern: "http://([^/]*)/.*", replace: "\\1", icase: TRUE );
			if(location != url){
				if( location != get_host_name() ){
					return NULL;
				}
				else {
					return remove_cgi_arguments( url: ereg_replace( string: url, pattern: "http://[^/]*/([^?]*)", replace: "/\\1", icase: TRUE ) );
				}
			}
		}
		else {
			if(ereg( pattern: "^https://", string: url, icase: TRUE )){
				location = ereg_replace( string: url, pattern: "https://([^/]*)/.*", replace: "\\1", icase: TRUE );
				if(location != url){
					if( location != get_host_name() ){
						return NULL;
					}
					else {
						return remove_cgi_arguments( url: ereg_replace( string: url, pattern: "https://[^/]*/([^?]*)", replace: "/\\1", icase: TRUE ) );
					}
				}
			}
		}
	}
	else {
		if(url == "//"){
			return make_list( "/",
				 url );
		}
		if(ereg( pattern: "^//.*", string: url, icase: TRUE )){
			location = ereg_replace( string: url, pattern: "//([^/]*)/.*", replace: "\\1", icase: TRUE );
			if(location != url){
				if(location == get_host_name()){
					return remove_cgi_arguments( url: ereg_replace( string: url, pattern: "//[^/]*/([^?]*)", replace: "/\\1", icase: TRUE ) );
				}
			}
			return NULL;
		}
		if( url[0] == "/" ){
			return remove_cgi_arguments( url: url );
		}
		else {
			i = 0;
			num_dots = 0;
			for(;i < strlen( url ) - 2 && url[i] == "." && url[i + 1] == "." && url[i + 2] == "/";){
				num_dots++;
				url = url - "../";
				if(strlen( url ) == 0){
					break;
				}
			}
			for(;i < strlen( url ) && url[i] == "." && url[i + 1] == "/";){
				url = url - "./";
				if(strlen( url ) == 0){
					break;
				}
			}
			for(;i < strlen( url ) - 2 && url[i] == "." && url[i + 1] == "." && url[i + 2] == "/";){
				num_dots++;
				url = url - "../";
				if(strlen( url ) == 0){
					break;
				}
			}
			url = NASLString( basename( name: current, level: num_dots ), url );
		}
		i = stridx( url, "#" );
		if(i >= 0){
			url = substr( url, 0, i - 1 );
		}
		if( url[0] != "/" ){
			return remove_cgi_arguments( url: NASLString( "/", url ) );
		}
		else {
			return remove_cgi_arguments( url: url );
		}
	}
	return NULL;
}
func basename( name, level ){
	var name, level;
	var len, i;
	len = strlen( name );
	if(len == 0){
		return NULL;
	}
	for(i = len - 1;i >= 0;i--){
		if(name[i] == "/"){
			level--;
			if(level < 0){
				return ( substr( name, 0, i ) );
			}
		}
	}
	return "/";
}
func check_recursion_candidates( url, current, port, host, debug, webmirror_called ){
	var url, current, port, host, debug, webmirror_called;
	var num;
	if(!url){
		return FALSE;
	}
	if(IsMatchRegexp( url, "^(https?|\\.|/|#)" )){
		if(debug > 3){
			display( "***** Not a recursion candidate: '", url );
		}
		return FALSE;
	}
	if(!ContainsString( url, "/" )){
		return FALSE;
	}
	num = recur_candidates[url];
	if( num ){
		num++;
		if(debug > 3){
			display( "***** Adding possible recursion candidate: '", url, "' (Count: ", num, ")" );
		}
		recur_candidates[url] = num;
		if(num > 2){
			if(debug > 3){
				display( "***** Max count ", num, " of recursion for: '", url, "' reached, skipping this URL." );
			}
			if(webmirror_called){
				set_kb_item( name: "www/" + host + "/" + port + "/content/recursion_urls", value: current + " (" + url + ")" );
			}
			return TRUE;
		}
	}
	else {
		if(debug > 3){
			display( "***** Adding possible recursion candidate: '", url, "' (Count: 1)" );
		}
		recur_candidates[url] = 1;
	}
	return FALSE;
}
func remove_cgi_arguments( url ){
	var url;
	var len, idx, cgi, cgi_args, _arg, args, a, b;
	if( isnull( url ) ) {
		return NULL;
	}
	else {
		if(!url){
			return make_list( url,
				 url );
		}
	}
	for(;url[strlen( url ) - 1] == " ";){
		url = substr( url, 0, strlen( url ) - 2 );
	}
	if( isnull( url ) ) {
		return NULL;
	}
	else {
		if(!url){
			return make_list( url,
				 url );
		}
	}
	len = strlen( url );
	idx = stridx( url, "?" );
	if( idx < 0 ){
		return make_list( url,
			 url );
	}
	else {
		if( idx >= len - 1 ){
			cgi = substr( url, 0, len - 2 );
			return make_list( cgi,
				 url,
				 "" );
		}
		else {
			if( idx > 1 ){
				cgi = substr( url, 0, idx - 1 );
			}
			else {
				cgi = ".";
			}
			cgi_args = split( buffer: substr( url, idx + 1, len - 1 ), sep: "&" );
			for _arg in make_list( cgi_args ) {
				_arg = _arg - "&";
				_arg = _arg - "amp;";
				a = ereg_replace( string: _arg, pattern: "(.*)=.*", replace: "\\1" );
				b = ereg_replace( string: _arg, pattern: ".*=(.*)", replace: "\\1" );
				if( a != b ){
					args = NASLString( args, a, " [", b, "] " );
				}
				else {
					args = NASLString( args, _arg, " [] " );
				}
			}
			return make_list( cgi,
				 url,
				 args );
		}
	}
}

