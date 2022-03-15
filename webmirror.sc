if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10662" );
	script_version( "2021-07-01T09:48:52+0000" );
	script_tag( name: "last_modification", value: "2021-07-01 09:48:52 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Web mirroring" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Renaud Deraison" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "no404.sc", "DDI_Directory_Scanner.sc", "global_settings.sc", "gb_ssl_sni_supported.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_add_preference( name: "Number of pages to mirror : ", type: "entry", value: "200" );
	script_add_preference( name: "Start page : ", type: "entry", value: "/" );
	script_add_preference( name: "Number of cgi directories to save into KB : ", type: "entry", value: "128" );
	script_add_preference( name: "Regex pattern to exclude cgi scripts : ", type: "entry", value: "\\.(js|css)$" );
	script_add_preference( name: "Use regex pattern to exclude cgi scripts : ", type: "checkbox", value: "yes" );
	script_tag( name: "summary", value: "This script makes a mirror of the remote web site
  and extracts the list of CGIs that are used by the remote host.

  It is suggested that you allow a long-enough timeout value for this test routine and also
  adjust the setting on the number of pages to mirror." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_timeout( 900 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("url_func.inc.sc");
start_page = script_get_preference( "Start page : " );
if(isnull( start_page ) || start_page == ""){
	start_page = "/";
}
max_pages = int( script_get_preference( "Number of pages to mirror : " ) );
if(max_pages <= 0){
	max_pages = 200;
}
replace_kb_item( name: "webmirror/max_pages_to_mirror", value: max_pages );
max_cgi_dirs = int( script_get_preference( "Number of cgi directories to save into KB : " ) );
if(max_cgi_dirs <= 0){
	max_cgi_dirs = 128;
}
replace_kb_item( name: "webmirror/max_dirs_in_kb", value: max_cgi_dirs );
cgi_dirs_exclude_pattern = get_kb_item( "global_settings/cgi_dirs_exclude_pattern" );
use_cgi_dirs_exclude_pattern = get_kb_item( "global_settings/use_cgi_dirs_exclude_pattern" );
cgi_dirs_exclude_servermanual = get_kb_item( "global_settings/cgi_dirs_exclude_servermanual" );
cgi_scripts_exclude_pattern = script_get_preference( "Regex pattern to exclude cgi scripts : " );
if(!cgi_scripts_exclude_pattern){
	cgi_scripts_exclude_pattern = "\\.(js|css)$";
}
replace_kb_item( name: "webmirror/cgi_scripts_exclude_pattern", value: cgi_scripts_exclude_pattern );
use_cgi_scripts_exclude_pattern = script_get_preference( "Use regex pattern to exclude cgi scripts : " );
failedReqs = 0;
currReqs = 0;
maxFailedReqs = 3;
num_cgi_dirs = 0;
debug = 0;
URLs_hash = make_list();
CGIs = make_list();
Dirs = make_list();
PW_inputs = make_list();
URLs_30x_hash = make_list();
URLs_auth_hash = make_list();
Code404 = make_list();
URLs_discovered = make_list();
Check401 = TRUE;
href_id_found = make_list();
URLs_hash[start_page] = 0;
cnt = 0;
RootPasswordProtected = FALSE;
Apache = FALSE;
iPlanet = FALSE;
func add_cgi_dir( dir, append_pattern, port, host ){
	var dir, append_pattern, port, host, req, res;
	dir = dir( url: dir );
	if(dir && !Dirs[dir]){
		if(num_cgi_dirs > max_cgi_dirs){
			set_kb_item( name: "www/" + host + "/" + port + "/content/skipped_directories", value: dir );
			return;
		}
		if(use_cgi_dirs_exclude_pattern){
			if(egrep( pattern: cgi_dirs_exclude_pattern, string: dir )){
				set_kb_item( name: "www/" + host + "/" + port + "/content/excluded_directories", value: dir );
				return;
			}
		}
		req = http_get( item: dir + "/non-existent-" + rand(), port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		currReqs++;
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 404" )){
			Dirs[dir] = 1;
			set_kb_item( name: "www/" + host + "/" + port + "/content/directories", value: dir );
			num_cgi_dirs++;
			if(isnull( URLs_hash[dir] )){
				URLs_discovered = make_list( URLs_discovered,
					 dir );
				if(append_pattern){
					if( Apache ){
						URLs_discovered = make_list( URLs_discovered,
							 dir + "/?D=A" );
					}
					else {
						if(iPlanet){
							URLs_discovered = make_list( URLs_discovered,
								 dir + "/?PageServices" );
						}
					}
				}
				URLs_hash[dir] = 0;
			}
		}
	}
}
func add_30x( url, port, host ){
	var url, port, host;
	if(isnull( URLs_30x_hash[url] )){
		set_kb_item( name: "www/" + host + "/" + port + "/content/30x", value: url );
		URLs_30x_hash[url] = 1;
	}
}
func add_auth( url, basic, realm, port, host ){
	var url, basic, realm, port, host;
	if(isnull( URLs_auth_hash[url] )){
		if(!Check401 && url != "/"){
			return;
		}
		set_kb_item( name: "www/content/auth_required", value: TRUE );
		set_kb_item( name: "www/" + host + "/" + port + "/content/auth_required", value: url );
		URLs_auth_hash[url] = 1;
		if(url == "/"){
			RootPasswordProtected = TRUE;
		}
		if(basic){
			set_kb_item( name: "www/basic_auth/detected", value: TRUE );
			set_kb_item( name: "www/pw_input_field_or_basic_auth/detected", value: TRUE );
			set_kb_item( name: "www/" + host + "/" + port + "/content/basic_auth/" + url, value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) + ":" + realm );
		}
	}
}
func add_url( url, port, host ){
	var url, port, host, ext, dir;
	if(url == "."){
		url = "/";
	}
	if(debug > 5){
		display( "**** ADD URL ", url );
	}
	if(isnull( URLs_hash[url] )){
		URLs_discovered = make_list( URLs_discovered,
			 url );
		URLs_hash[url] = 0;
		url = ereg_replace( string: url, pattern: "(.*)[;?].*", replace: "\\1" );
		ext = ereg_replace( pattern: ".*\\.([^\\.]*)$", string: url, replace: "\\1" );
		if(strlen( ext ) && ext[0] != "/"){
			set_kb_item( name: "www/" + host + "/" + port + "/content/extensions/" + ext, value: url );
			if(ext == "action" || ext == "jsp" || ext == "do"){
				set_kb_item( name: "www/action_jsp_do", value: TRUE );
			}
			if(ext == "xhtml" || ext == "jsf" || ext == "faces"){
				set_kb_item( name: "www/javaserver_faces/detected", value: TRUE );
			}
		}
		add_cgi_dir( dir: url, append_pattern: TRUE, port: port, host: host );
	}
}
func cgi2hash( cgi ){
	var cgi, cur_cgi, cur_arg, i, ret, len;
	ret = make_list();
	len = strlen( cgi );
	for(i = 0;i < len;i++){
		if(cgi[i] == " " && i + 1 < len && cgi[i + 1] == "["){
			cur_arg = "";
			for(i = i + 2;i < len;i++){
				if( cgi[i] == "]" ){
					ret[cur_cgi] = cur_arg;
					cur_cgi = "";
					cur_arg = "";
					if(i + 2 >= len){
						return ret;
					}
					i += 2;
					break;
				}
				else {
					cur_arg += cgi[i];
				}
			}
		}
		cur_cgi += cgi[i];
	}
	return ret;
}
func hash2cgi( hash ){
	var hash, ret, h;
	ret = "";
	for h in keys( hash ) {
		ret += NASLString( h, " [", hash[h], "] " );
	}
	return ret;
}
func add_cgi( cgi, original_url, args, port, host ){
	var cgi, original_url, args, port, host;
	var tmp, new_args, common, c;
	if(ContainsString( cgi, "/?D=A" ) || ContainsString( cgi, "/?PageServices" )){
		return;
	}
	if(cgi == "."){
		cgi = "/";
	}
	args = NASLString( args );
	if( isnull( CGIs[cgi] ) ){
		CGIs[cgi] = args;
		add_cgi_dir( dir: cgi, port: port, host: host );
		args = CGIs[cgi];
		if(!args){
			args = "";
		}
		if(use_cgi_scripts_exclude_pattern != "no"){
			if(egrep( pattern: cgi_scripts_exclude_pattern, string: cgi )){
				replace_kb_item( name: "www/" + host + "/" + port + "/content/excluded_cgis/" + cgi, value: http_report_vuln_url( port: port, url: cgi, url_only: TRUE ) + " (" + args + ")" );
				return;
			}
		}
		set_kb_item( name: "www/" + host + "/" + port + "/content/cgis/plain_cgis", value: cgi + " - " + args );
		replace_kb_item( name: "www/" + host + "/" + port + "/content/cgis/cgis_reporting/" + cgi, value: http_report_vuln_url( port: port, url: cgi, url_only: TRUE ) + " (" + args + ")" );
		if(original_url){
			set_kb_item( name: "www/" + host + "/" + port + "/content/cgis/full_cgis", value: original_url );
		}
	}
	else {
		tmp = cgi2hash( cgi: CGIs[cgi] );
		new_args = cgi2hash( cgi: args );
		common = make_list();
		for c in keys( tmp ) {
			common[c] = tmp[c];
		}
		for c in keys( new_args ) {
			if(isnull( common[c] )){
				common[c] = new_args[c];
			}
		}
		CGIs[cgi] = hash2cgi( hash: common );
		args = CGIs[cgi];
		if(!args){
			args = "";
		}
		if(use_cgi_scripts_exclude_pattern != "no"){
			if(egrep( pattern: cgi_scripts_exclude_pattern, string: cgi )){
				replace_kb_item( name: "www/" + host + "/" + port + "/content/excluded_cgis/" + cgi, value: http_report_vuln_url( port: port, url: cgi, url_only: TRUE ) + " (" + args + ")" );
				return;
			}
		}
		set_kb_item( name: "www/" + host + "/" + port + "/content/cgis/plain_cgis", value: cgi + " - " + args );
		replace_kb_item( name: "www/" + host + "/" + port + "/content/cgis/cgis_reporting/" + cgi, value: http_report_vuln_url( port: port, url: cgi, url_only: TRUE ) + " (" + args + ")" );
		if(original_url){
			set_kb_item( name: "www/" + host + "/" + port + "/content/cgis/full_cgis", value: original_url );
		}
	}
}
func dir( url ){
	var url;
	return ereg_replace( pattern: "(.*)/[^/]*", string: url, replace: "\\1" );
}
func extract_location( data, port, host ){
	var data, port, host;
	var loc, url;
	loc = egrep( string: data, pattern: "^Location\\s*:", icase: TRUE );
	if(!loc){
		return NULL;
	}
	loc = loc - NASLString( "\\r\\n" );
	loc = ereg_replace( string: loc, pattern: "Location\\s*:\\s*(.*)$", replace: "\\1" );
	url = canonical_url( url: loc, current: "/", port: port, host: host, debug: debug, webmirror_called: TRUE );
	if(url){
		if(!isnull( url[2] )){
			add_cgi( cgi: url[0], original_url: url[1], args: url[2], port: port, host: host );
		}
		add_url( url: url[0], port: port, host: host );
		return url;
	}
	return NULL;
}
func retr( port, page, host ){
	var port, page, host;
	var req, res, basic_auth, q;
	if(debug){
		display( "*** RETR ", page );
	}
	req = http_get_req( url: page, port: port, accept_header: "text/html, text/xml" );
	res = http_keepalive_send_recv( port: port, data: req, fetch404: TRUE, content_type_body_only: "^Content-Type\\s*:\\s*text/(xml|html)", bodyonly: FALSE );
	currReqs++;
	if(!res){
		failedReqs++;
		if(failedReqs >= maxFailedReqs){
			if(debug){
				display( "*** Max number of failed requests (" + maxFailedReqs + ") reached (Amount of requests done: " + currReqs + ") + exiting..." );
			}
			exit( 0 );
		}
		return NULL;
	}
	if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 40[13]" )){
			if(egrep( pattern: "^WWW-Authenticate\\s*:", string: res, icase: TRUE )){
				basic_auth = http_extract_basic_auth( data: res );
				add_auth( url: page, basic: basic_auth["basic_auth"], realm: basic_auth["realm"], port: port, host: host );
			}
			return NULL;
		}
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 30[0-8]" )){
			q = egrep( pattern: "^Location\\s*:.*", string: res, icase: TRUE );
			add_30x( url: page, port: port, host: host );
			if(!( ( ContainsString( page, "?PageServices" ) || ContainsString( page, "?D=A" ) ) && ( ContainsString( q, "?PageServices" ) || ContainsString( q, "?D=A" ) ) )){
				extract_location( data: res, port: port, host: host );
			}
			return NULL;
		}
	}
	if( egrep( pattern: "^Server\\s*:.*Apache.*", string: res, icase: TRUE ) ){
		Apache = TRUE;
	}
	else {
		if(egrep( pattern: "^Server\\s*:.*Netscape.*", string: res, icase: TRUE )){
			iPlanet = TRUE;
		}
	}
	if( !egrep( pattern: "^Content-Type\\s*:\\s*text/(xml|html).*", string: res, icase: TRUE ) ){
		return NULL;
	}
	else {
		res = strstr( res, NASLString( "\\r\\n\\r\\n" ) );
		if(!res){
			return NULL;
		}
		res = str_replace( string: res, find: NASLString( "\\r\\n" ), replace: " " );
		res = str_replace( string: res, find: NASLString( "\\n" ), replace: " " );
		res = str_replace( string: res, find: NASLString( "\\t" ), replace: " " );
		return res;
	}
}
func token_split( content ){
	var content, num, ret, len, i, j, k, str;
	num = 0;
	ret = make_list();
	len = strlen( content );
	for(i = 0;i < len;i++){
		if( ( ( i + 3 ) < len ) && content[i] == "<" && content[i + 1] == "!" && content[i + 2] == "-" && content[i + 3] == "-" ){
			j = stridx( content, "-->", i );
			if(j < 0){
				return ret;
			}
			i = j;
		}
		else {
			if(content[i] == "<"){
				str = "";
				i++;
				for(;content[i] == " ";){
					i++;
				}
				for(j = i;j < len;j++){
					if( content[j] == "\"" ){
						k = stridx( content, "\"", j + 1 );
						if(k < 0){
							return ret;
						}
						str += substr( content, j, k );
						j = k;
					}
					else {
						if( content[j] == ">" ){
							if(ereg( pattern: "^(a|area|frame|meta|iframe|link|img|form|/form|input|button|textarea|select|applet|script)( .*|$)", string: str, icase: TRUE )){
								num++;
								ret = make_list( ret,
									 str );
								if(num > 500){
									return ret;
								}
							}
							break;
						}
						else {
							str += content[j];
						}
					}
				}
				i = j;
			}
		}
	}
	return ret;
}
func token_parse( token ){
	var token, ret, len, current_word, word_index, i, j, current_value, char;
	ret = make_list();
	len = strlen( token );
	current_word = "";
	word_index = 0;
	for(i = 0;i < len;i++){
		if( ( token[i] == " " ) || ( token[i] == "=" ) ){
			for(;i + 1 < len && token[i + 1] == " ";){
				i++;
			}
			if(i >= len){
				break;
			}
			if( word_index == 0 ){
				ret["nasl_token_type"] = tolower( current_word );
			}
			else {
				for(;i + 1 < len && token[i] == " ";){
					i++;
				}
				if( token[i] != "=" ){
					ret[tolower( current_word )] = NULL;
				}
				else {
					i++;
					char = NULL;
					if(i >= len){
						break;
					}
					if( token[i] == "\"" ){
						char = "\"";
					}
					else {
						if(token[i] == "'"){
							char = "'";
						}
					}
					if( !isnull( char ) ){
						j = stridx( token, char, i + 1 );
						if(j < 0){
							if(debug){
								display( "PARSE ERROR 1" );
							}
							return ret;
						}
						ret[tolower( current_word )] = substr( token, i + 1, j - 1 );
						for(;j + 1 < len && token[j + 1] == " ";){
							j++;
						}
						i = j;
					}
					else {
						j = stridx( token, " ", i + 1 );
						if(j < 0){
							j = len;
						}
						ret[tolower( current_word )] = substr( token, i, j - 1 );
						i = j;
					}
				}
			}
			current_word = "";
			word_index++;
		}
		else {
			if(i < len){
				current_word = current_word + token[i];
			}
		}
	}
	if(!word_index){
		ret["nasl_token_type"] = tolower( current_word );
	}
	return ret;
}
func parse_java( elements, port, host ){
	var elements, port, host;
	var archive, code, codebase;
	archive = elements["archive"];
	code = elements["code"];
	codebase = elements["codebase"];
	if( codebase ){
		if(archive){
			set_kb_item( name: "www/" + host + "/" + port + "/content/java_classfile", value: codebase + "/" + archive );
		}
		if(code){
			set_kb_item( name: "www/" + host + "/" + port + "/content/java_classfile", value: codebase + "/" + code );
		}
	}
	else {
		if(archive){
			set_kb_item( name: "www/" + host + "/" + port + "/content/java_classfile", value: archive );
		}
		if(code){
			set_kb_item( name: "www/" + host + "/" + port + "/content/java_classfile", value: code );
		}
	}
}
func parse_javascript( elements, current, port, host ){
	var elements, current, port, host;
	var url, pat;
	if(debug > 15){
		display( "*** JAVASCRIPT" );
	}
	pat = NASLString( ".*window\\\\.open\\\\('([^',", raw_string( 0x29 ), "]*)'.*\\\\)*" );
	url = ereg_replace( pattern: pat, string: elements["onclick"], replace: "\\1", icase: TRUE );
	if(url == elements["onclick"]){
		return NULL;
	}
	url = canonical_url( url: url, current: current, port: port, host: host, debug: debug, webmirror_called: TRUE );
	if(url){
		if(!isnull( url[2] )){
			add_cgi( cgi: url[0], original_url: url[1], args: url[2], port: port, host: host );
		}
		add_url( url: url[0], port: port, host: host );
		return url[0];
	}
	return NULL;
}
func parse_dir_from_src( elements, current, port, host ){
	var elements, current, port, host, src;
	src = elements["src"];
	if(!src){
		return NULL;
	}
	src = canonical_url( url: src, current: current, port: port, host: host, debug: debug, webmirror_called: TRUE );
	if(src){
		if(!isnull( src[2] )){
			add_cgi( cgi: src[0], original_url: src[1], args: src[2], port: port, host: host );
		}
		add_cgi_dir( dir: src[0], port: port, host: host );
	}
}
func parse_href_or_src( elements, current, port, host ){
	var elements, current, port, host;
	var href;
	href = elements["href"];
	if(!href){
		href = elements["src"];
	}
	if(!href){
		return NULL;
	}
	href = canonical_url( url: href, current: current, port: port, host: host, debug: debug, webmirror_called: TRUE );
	if(href){
		if(!isnull( href[2] )){
			add_cgi( cgi: href[0], original_url: href[1], args: href[2], port: port, host: host );
		}
		add_url( url: href[0], port: port, host: host );
		return href[0];
	}
}
func parse_a_href_id( elements, current, port, host ){
	var elements, current, port, host;
	var href, id, kb_key;
	href = elements["href"];
	id = elements["id"];
	if(!href || isnull( id )){
		return NULL;
	}
	href = canonical_url( url: href, current: current, port: port, host: host, debug: debug, webmirror_called: TRUE );
	if(href){
		if(id == ""){
			id = "empty";
		}
		kb_key = href[0] + "###---###---###" + id;
		if(!href_id_found[kb_key]){
			href_id_found[kb_key] = 1;
			set_kb_item( name: "www/href_id/available", value: TRUE );
			set_kb_item( name: "www/" + host + "/" + port + "/content/href_id", value: kb_key );
		}
		return make_array( href[0], id );
	}
}
func parse_refresh( elements, current, port, host ){
	var elements, current, port, host;
	var content, t, sub, href;
	if(elements["content"] == "0"){
		return NULL;
	}
	content = elements["content"];
	if(!content){
		return NULL;
	}
	t = strstr( content, ";" );
	if(!isnull( t )){
		content = substr( t, 1, strlen( t ) - 1 );
	}
	content = NASLString( "a ", content );
	sub = token_parse( token: content );
	if(isnull( sub )){
		return NULL;
	}
	href = sub["url"];
	if(!href){
		return NULL;
	}
	href = canonical_url( url: href, current: current, port: port, host: host, debug: debug, webmirror_called: TRUE );
	if(href){
		if(!isnull( href[2] )){
			add_cgi( cgi: href[0], original_url: href[1], args: href[2], port: port, host: host );
		}
		add_url( url: href[0], port: port, host: host );
		return href[0];
	}
}
func parse_form( elements, current, port, host ){
	var elements, current, port, host;
	var action;
	action = elements["action"];
	if(!isnull( action ) && ( action == "" || action == "#" )){
		action = current;
	}
	action = canonical_url( url: action, current: current, port: port, host: host, debug: debug, webmirror_called: TRUE );
	if( action ){
		if(!isnull( action[2] )){
			add_cgi( cgi: action[0], original_url: action[1], args: action[2], port: port, host: host );
		}
		return action[0];
	}
	else {
		return NULL;
	}
}
func pre_parse( src_page, data, port, host ){
	var src_page, data, port, host;
	var js_data, js_src, data2, php_path, fp_save;
	if(js_data = eregmatch( string: data, pattern: "<script( type=(\'text/javascript\'|\"text/javascript\"|\'application/javascript\'|\"application/javascript\"))?>(.*)</script>", icase: TRUE )){
		if(ContainsString( js_data[3], "CoinHive.Anonymous" ) || ContainsString( js_data[3], "CoinHive.User" ) || ContainsString( js_data[3], "CoinHive.Token" )){
			set_kb_item( name: "www/coinhive/detected", value: TRUE );
			if( ContainsString( js_data[3], ".didOptOut" ) ){
				set_kb_item( name: "www/" + host + "/" + port + "/content/coinhive_optout", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
			}
			else {
				if( ContainsString( js_data[3], "https://authedmine.com/lib/authedmine.min.js" ) ){
					set_kb_item( name: "www/" + host + "/" + port + "/content/coinhive_optin", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
				}
				else {
					set_kb_item( name: "www/" + host + "/" + port + "/content/coinhive_nooptout", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
				}
			}
		}
		if(ContainsString( js_data[3], "();\",\"\\x7C\",\"\\x73\\x70\\x6C\\x69\\x74\",\"" ) && ContainsString( js_data[3], "\\x43\\x72\\x79\\x70\\x74\\x6F\\x6E\\x69\\x67\\x68\\x74\\x57\\x41\\x53\\x4D\\x57\\x72\\x61\\x70\\x70\\x65\\x72" )){
			set_kb_item( name: "www/coinhive/detected", value: TRUE );
			set_kb_item( name: "www/" + host + "/" + port + "/content/coinhive_obfuscated", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
		}
	}
	if(js_src = eregmatch( string: data, pattern: "<script [^>]+src=[\"\']([^\"\']+)[\"\']", icase: TRUE )){
		if(IsMatchRegexp( js_src[1], "^https?://" ) && ( ContainsString( js_src[1], "mage.js" ) || IsMatchRegexp( js_src[1], "poter[0-9.]+\\.js" ) )){
			set_kb_item( name: "www/compromised_webapp/detected", value: TRUE );
			set_kb_item( name: "www/" + host + "/" + port + "/content/compromised_webapp", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) + "#----#" + js_src[0] + "#----#Magentocore.net Skimmer, https://gwillem.gitlab.io/2018/08/30/magentocore.net_skimmer_most_aggressive_to_date/" );
		}
	}
	if(ContainsString( data, "Index of /" )){
		if(!ContainsString( src_page, "?D=A" ) && !ContainsString( src_page, "?PageServices" )){
			set_kb_item( name: "www/" + host + "/" + port + "/content/dir_index", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
		}
	}
	if(ContainsString( data, "<title>phpinfo()</title>" )){
		set_kb_item( name: "php/phpinfo/detected", value: TRUE );
		set_kb_item( name: "php/phpinfo/" + host + "/" + port + "/detected", value: TRUE );
		set_kb_item( name: "www/" + host + "/" + port + "/content/phpinfo_script/plain", value: src_page );
		set_kb_item( name: "www/" + host + "/" + port + "/content/phpinfo_script/reporting", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
	}
	if(ContainsString( data, "Fatal" ) || ContainsString( data, "Warning" )){
		data2 = strstr( data, "Fatal" );
		if(!data2){
			data2 = strstr( data, "Warning" );
		}
		data2 = strstr( data2, "in <b>" );
		php_path = ereg_replace( pattern: "in <b>([^<]*)</b>.*", string: data2, replace: "\\1" );
		if(php_path != data2){
			set_kb_item( name: "www/" + host + "/" + port + "/content/php_physical_path", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) + " (" + php_path + ")" );
		}
	}
	data2 = strstr( data, "unescape" );
	if(data2 && ereg( pattern: "unescape..(%([0-9]|[A-Z])*){200,}.*", string: data2 )){
		set_kb_item( name: "www/" + host + "/" + port + "/content/guardian", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
	}
	if(ContainsString( data, "CREATED WITH THE APPLET PASSWORD WIZARD WWW.COFFEECUP.COM" )){
		set_kb_item( name: "www/" + host + "/" + port + "/content/coffeecup", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) );
	}
	if(ContainsString( data, "SaveResults" )){
		fp_save = ereg_replace( pattern: "(.*SaveResults.*U-File=)\"(.*)\".*", string: data, replace: "\\2" );
		if(fp_save != data){
			set_kb_item( name: "www/" + host + "/" + port + "/content/frontpage_results", value: http_report_vuln_url( port: port, url: src_page, url_only: TRUE ) + " (" + fp_save + ")" );
		}
	}
	if(ContainsString( data, "javax.faces.resource" )){
		set_kb_item( name: "www/javaserver_faces/detected", value: TRUE );
	}
}
func parse_main( current, data, port, host ){
	var current, data, port, host;
	var form_cgis, form_cgis_level, argz, store_cgi, token, tokens, elements, cgi;
	form_cgis = make_list();
	form_cgis_level = 0;
	argz = NULL;
	store_cgi = 0;
	tokens = token_split( content: data );
	for token in tokens {
		elements = token_parse( token: token );
		if(!isnull( elements )){
			if(elements["onclick"]){
				parse_javascript( elements: elements, current: current, port: port, host: host );
			}
			if(elements["nasl_token_type"] == "applet"){
				parse_java( elements: elements, port: port, host: host );
			}
			if(elements["nasl_token_type"] == "a" || elements["nasl_token_type"] == "link" || elements["nasl_token_type"] == "frame" || elements["nasl_token_type"] == "iframe" || elements["nasl_token_type"] == "area"){
				if(isnull( parse_href_or_src( elements: elements, current: current, port: port, host: host ) )){
					if(debug > 20){
						display( "ERROR - ", token );
					}
				}
			}
			if(elements["nasl_token_type"] == "a" && !isnull( elements["href"] )){
				if(isnull( parse_a_href_id( elements: elements, current: current, port: port, host: host ) )){
					if(debug > 20){
						display( "ERROR - ", token );
					}
				}
			}
			if(elements["nasl_token_type"] == "img" || elements["nasl_token_type"] == "script"){
				parse_dir_from_src( elements: elements, current: current, port: port, host: host );
			}
			if(elements["nasl_token_type"] == "meta"){
				parse_refresh( elements: elements, current: current, port: port, host: host );
			}
			if(elements["nasl_token_type"] == "form"){
				cgi = parse_form( elements: elements, current: current, port: port, host: host );
				if(cgi){
					form_cgis[form_cgis_level] = cgi;
					store_cgi = 1;
				}
				form_cgis_level++;
			}
			if(elements["nasl_token_type"] == "/form"){
				form_cgis_level--;
				if(form_cgis_level < 0){
					form_cgis_level = 0;
				}
				if(store_cgi != 0){
					add_cgi( cgi: form_cgis[form_cgis_level], args: argz, port: port, host: host );
				}
				argz = "";
				store_cgi = 0;
			}
			if(elements["nasl_token_type"] == "input" || elements["nasl_token_type"] == "select"){
				if(elements["name"]){
					argz += NASLString( elements["name"], " [", elements["value"], "] " );
				}
				if(elements["name"] && elements["type"] == "password"){
					if(!PW_inputs[current]){
						PW_inputs[current] = 1;
						set_kb_item( name: "www/pw_input_field/detected", value: TRUE );
						set_kb_item( name: "www/pw_input_field_or_basic_auth/detected", value: TRUE );
						set_kb_item( name: "www/" + host + "/" + port + "/content/pw_input_field/" + current, value: http_report_vuln_url( port: port, url: current, url_only: TRUE ) + ":" + elements["name"] );
					}
				}
			}
		}
	}
}
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
dirs = http_cgi_dirs( port: port, host: host );
if( dirs ){
	URLs_start = nasl_make_list_unique( start_page, dirs );
}
else {
	URLs_start = make_list( start_page );
}
redirects = get_kb_list( "DDI_Directory_Scanner/" + host + "/" + port + "/received_redirects" );
if(redirects){
	URLs_start = make_list( URLs_start,
		 redirects );
}
req = http_get( item: "/NonExistent" + rand() + "/", port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
currReqs++;
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 401" )){
	if(debug){
		display( "*** This server requires authentication for non-existent directories, disabling 401 checks." );
	}
	Check401 = FALSE;
}
URLs = URLs_start;
for(;TRUE;){
	for URL in URLs {
		if(!URLs_hash[URL]){
			if(cgi_dirs_exclude_servermanual){
				if(IsMatchRegexp( URL, "^/manual" )){
					res = http_get_cache( item: "/manual/en/index.html", port: port );
					currReqs++;
					if(ContainsString( res, "Documentation - Apache HTTP Server" )){
						URLs_hash[URL] = 1;
						set_kb_item( name: "www/" + host + "/" + port + "/content/servermanual_directories", value: http_report_vuln_url( port: port, url: URL, url_only: TRUE ) + ", Content: Apache HTTP Server Manual" );
						continue;
					}
				}
				if(IsMatchRegexp( URL, "^/tomcat-docs" )){
					res = http_get_cache( item: "/tomcat-docs/", port: port );
					currReqs++;
					if(ContainsString( res, "Apache Tomcat" ) && ContainsString( res, "Documentation Index" )){
						URLs_hash[URL] = 1;
						set_kb_item( name: "www/" + host + "/" + port + "/content/servermanual_directories", value: http_report_vuln_url( port: port, url: URL, url_only: TRUE ) + ", Content: Apache Tomcat Documentation" );
						continue;
					}
				}
			}
			page = retr( port: port, page: URL, host: host );
			cnt++;
			pre_parse( src_page: URL, data: page, port: port, host: host );
			parse_main( data: page, current: URL, port: port, host: host );
			URLs_hash[URL] = 1;
			if(cnt >= max_pages){
				if(debug){
					display( "*** Max pages ", max_pages, " reached, stopping test." );
				}
				set_kb_item( name: "www/" + host + "/" + port + "/content/max_pages_reached", value: TRUE );
				break;
			}
		}
	}
	if( max_index( URLs_discovered ) > 0 ){
		URLs = URLs_discovered;
		URLs_discovered = make_list();
	}
	else {
		break;
	}
}
if(cnt == 1){
	if(RootPasswordProtected){
		set_kb_item( name: "www/" + host + "/" + port + "/password_protected", value: TRUE );
	}
}
if(debug){
	display( "*** Finished scan (Done requests: ", currReqs, "), exiting..." );
}
exit( 0 );

