if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10386" );
	script_version( "2020-11-27T13:32:50+0000" );
	script_tag( name: "last_modification", value: "2020-11-27 13:32:50 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Response Time / No 404 Error Code Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 RD / H D Moore" );
	script_family( "Web Servers" );
	script_dependencies( "http_login.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_add_preference( name: "Maximum response time (in seconds)", type: "entry", value: "60", id: 1 );
	script_tag( name: "insight", value: "This web server might show the following issues:

  - it is [mis]configured in that it does not return '404 Not Found' error codes when a non-existent
  file is requested, perhaps returning a site map, search page, authentication page or redirect instead.

  The Scanner might enabled some counter measures for that, however they might be insufficient. If a
  great number of security issues are reported for this port, they might not all be accurate.

  - it doesn't response in a reasonable amount of time to various HTTP requests sent by this VT.

  In order to keep the scan total time to a reasonable amount, the remote web server might not be
  tested. If the remote server should be tested it has to be fixed to have it reply to the scanners
  requests in a reasonable amount of time.

  Alternatively the 'Maximum response time (in seconds)' preference could be raised to a higher
  value if longer scan times are accepted." );
	script_tag( name: "summary", value: "This VT tests if the remote web server does not reply with a 404
  error code and checks if it is replying to the scanners requests in a reasonable amount of time." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("404.inc.sc");
var max_response_time, basename, badurls;
debug = 0;
func find_err_msg( buffer ){
	var buffer;
	var errmsg;
	for errmsg in errmessages_404 {
		if(egrep( pattern: errmsg, string: buffer, icase: TRUE )){
			errmsg = str_replace( string: errmsg, find: "\\", replace: "" );
			if(debug){
				display( "no404 - \"" + errmsg + "\" found in \"" + buffer );
			}
			return errmsg;
		}
	}
	return 0;
}
basename = "404";
for(;ContainsString( basename, "404" );){
	basename = "/" + rand_str( length: 12 );
}
badurls = make_list( "/cgi-bin" + basename + ".html",
	 "/cgi-bin" + basename + ".htm",
	 "/cgi-bin" + basename + ".cgi",
	 "/cgi-bin" + basename + ".sh",
	 "/cgi-bin" + basename + ".pl",
	 "/cgi-bin" + basename + ".inc",
	 "/cgi-bin" + basename + ".shtml",
	 "/cgi-bin" + basename + ".php",
	 "/cgi-bin" + basename + ".php3",
	 "/cgi-bin" + basename + ".php4",
	 "/cgi-bin" + basename + ".php5",
	 "/cgi-bin" + basename + ".php7",
	 "/cgi-bin" + basename + ".cfm",
	 "/scripts" + basename + ".html",
	 "/scripts" + basename + ".htm",
	 "/scripts" + basename + ".cgi",
	 "/scripts" + basename + ".sh",
	 "/scripts" + basename + ".pl",
	 "/scripts" + basename + ".inc",
	 "/scripts" + basename + ".shtml",
	 "/scripts" + basename + ".php",
	 "/scripts" + basename + ".php3",
	 "/scripts" + basename + ".php4",
	 "/scripts" + basename + ".php5",
	 "/scripts" + basename + ".php7",
	 "/scripts" + basename + ".cfm" );
max_response_time = int( script_get_preference( name: "Maximum response time (in seconds)", id: 1 ) );
if(max_response_time <= 0){
	max_response_time = 60;
}
func my_exit( then, port, host ){
	var then, port, host;
	var now, report;
	now = unixtime();
	if(now - then > max_response_time){
		report = "The remote web server is very slow - it took " + int( now - then ) + " seconds " + "(Maximum response time configured in 'Response Time / No 404 Error Code Check' " + "(OID: 1.3.6.1.4.1.25623.1.0.10386) preferences: " + max_response_time + " seconds) to " + "execute the plugin no404.nasl (it usually only takes a few seconds)." + "\n\n" + "In order to keep the scan total time to a reasonable amount, the remote web server " + "has not been tested." + "\n\n" + "If the remote server should be tested it has to be fixed to have it reply to the scanners " + "requests in a reasonable amount of time. Alternatively the 'Maximum response time (in seconds)' " + "preference could be raised to a higher value if longer scan times are accepted.";
		log_message( port: port, data: report );
		http_set_is_marked_broken( port: port, host: host, reason: report );
	}
	exit( 0 );
}
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: "^Server\\s*:\\s*MiniServ", string: banner, icase: TRUE )){
	reason = "The 'MiniServ' embedded server was found which is fragile when getting scanned. HTTP scanning will be disabled for this host.";
	http_set_no404_string( port: port, host: host, string: "HTTP" );
	http_set_is_marked_broken( port: port, host: host, reason: reason );
	log_message( port: port, data: reason );
	exit( 0 );
}
if(egrep( pattern: "^Server\\s*:\\s*MailEnable-HTTP", string: banner, icase: TRUE )){
	reason = "The 'MailEnable-HTTP' server was found which is fragile when getting scanned. HTTP scanning will be disabled for this host.";
	http_set_no404_string( port: port, host: host, string: "HTTP" );
	http_set_is_marked_broken( port: port, host: host, reason: reason );
	log_message( port: port, data: reason );
	exit( 0 );
}
if(egrep( pattern: "^Server\\s*:\\s*CompaqHTTPServer", string: banner, icase: TRUE )){
	reason = "The 'CompaqHTTPServer' server was found which is fragile when getting scanned. HTTP scanning will be disabled for this host.";
	http_set_no404_string( port: port, host: host, string: "HTTP" );
	http_set_is_marked_broken( port: port, host: host, reason: reason );
	log_message( port: port, data: reason );
	exit( 0 );
}
if(egrep( pattern: "^DAAP-Server\\s*:", string: banner, icase: TRUE )){
	reason = "A 'DAAP-Server' was found which is no real web server. HTTP scanning will be disabled for this host.";
	http_set_is_marked_broken( port: port, host: host, reason: reason );
	log_message( port: port, data: reason );
	exit( 0 );
}
url = "/";
res = http_get_cache( item: url, port: port );
if(res && res == "HTTP/1.0 403 Access Denied\r\n\r\n\r\nWeb Access is not enabled.\r\n"){
	reason = "A ZNC IRC Bouncer with disabled Web Access was found. HTTP scanning will be disabled for this host.";
	http_set_is_marked_broken( port: port, host: host, reason: reason );
	log_message( port: port, data: reason );
	exit( 0 );
}
if(IsMatchRegexp( banner, "^HTTP/1\\.[01] 30[0-8]" ) || egrep( string: banner, pattern: "^Location\\s*:", icase: TRUE )){
	redirect = http_extract_location_from_redirect( port: port, data: banner, dir_only: TRUE, current_dir: url );
	if(redirect){
		basename = redirect + basename;
	}
}
badurls = make_list( basename + ".html",
	 basename + ".htm",
	 basename + ".cgi",
	 basename + ".sh",
	 basename + ".pl",
	 basename + ".inc",
	 basename + ".shtml",
	 basename + ".asp",
	 basename + ".php",
	 basename + ".php3",
	 basename + ".php4",
	 basename + ".php5",
	 basename + ".php7",
	 basename + ".cfm",
	 badurls );
then = unixtime();
counter = 0;
report = "The service is responding with a 200 HTTP status code to non-existent files/urls. ";
report += "The following pattern is used to work around possible false detections:";
report += "\n-----\n";
for badurl in badurls {
	if(debug){
		display( "no404 - Checking URL " + badurl + " on port " + port );
	}
	req = http_get( item: badurl, port: port );
	res = http_keepalive_send_recv( data: req, port: port );
	if(!res){
		counter++;
		if(debug){
			display( "no404 - An error occurred when trying to request: " + badurl );
		}
		continue;
	}
	if(counter > 3){
		if(debug){
			display( "no404 - Too many failed requests, exiting..." );
		}
		exit( 0 );
	}
	raw_http_line = egrep( pattern: "^HTTP/", string: res );
	if( ereg( pattern: "^HTTP/1\\.[01] 200", string: raw_http_line ) ){
		not_found = find_err_msg( buffer: res );
		if( not_found != 0 ){
			if(debug){
				display( "no404 - 200: Using string: " + not_found );
			}
			http_set_no404_string( port: port, host: host, string: NASLString( not_found ) );
			report += NASLString( not_found ) + "\n-----";
			log_message( port: port, data: report );
			my_exit( then: then, port: port, host: host );
		}
		else {
			title = egrep( pattern: "<title", string: res, icase: TRUE );
			if(title){
				title = ereg_replace( string: title, pattern: ".*<title>(.*)</title>.*", replace: "\\1", icase: TRUE );
				if(title){
					if(debug){
						display( "no404 - using string from title tag: " + title );
					}
					http_set_no404_string( port: port, host: host, string: title );
					report += NASLString( title ) + "\n-----";
					log_message( port: port, data: report );
					my_exit( then: then, port: port, host: host );
				}
			}
			body = egrep( pattern: "<body", string: res, icase: TRUE );
			if(body){
				body = ereg_replace( string: body, pattern: "<body(.*)>", replace: "\\1", icase: TRUE );
				if(body){
					if(debug){
						display( "no404 - using string from body tag: " + body );
					}
					http_set_no404_string( port: port, host: host, string: body );
					report += body + "\n-----";
					log_message( port: port, data: report );
					my_exit( then: then, port: port, host: host );
				}
			}
			if(debug){
				display( "no404 - argh! could not find something to match against." );
			}
			if(debug){
				display( "no404 - [response] " + res );
			}
			http_set_no404_string( port: port, host: host, string: "HTTP" );
			log_message( port: port, data: "The host does not return '404 Not Found' error codes when a non-existent file is requested and it wasn't possible to find a common error message interpreted as a 404. Some HTTP-related checks have been disabled." );
			my_exit( then: then, port: port, host: host );
		}
	}
	else {
		if(ereg( pattern: "^HTTP/1\\.[01] 30[0-8]", string: raw_http_line )){
			has_redirect = TRUE;
		}
	}
}
if(has_redirect){
	log_message( port: port, data: "The host returns a 30x (e.g. 301) error code when a non-existent file is requested. Some HTTP-related checks have been disabled." );
}
my_exit( then: then, port: port, host: host );

