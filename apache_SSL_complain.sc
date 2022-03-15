if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15588" );
	script_version( "2021-03-02T12:11:43+0000" );
	script_tag( name: "last_modification", value: "2021-03-02 12:11:43 +0000 (Tue, 02 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Detect HTTP Traffic sent to SSL/TLS enabled Web Server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Enable 'Test SSL based services' in the 'Services' preference setting,
  or increase the timeouts if this option is already set and the plugin missed this port." );
	script_tag( name: "summary", value: "This script tries to detect if there is an SSL/TLS detection issue which
  might impede the scan results." );
	script_tag( name: "insight", value: "The scanner has discovered that it is talking in plain HTTP on a SSL/TLS port
  and has tried to corrected this issue by enabled HTTPS on this port only. However if other SSL/TLS ports are used
  on the remote host, they might be skipped." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
func create_http_req( port, httpver ){
	var port, httpver;
	if( httpver == "11" ){
		host = http_host_name( port: port );
		return NASLString( "GET / HTTP/1.1\r\nHost: ", host, "\r\n\r\n" );
	}
	else {
		return NASLString( "GET / HTTP/1.0\r\n\r\n" );
	}
}
banners = get_kb_list( "FindService/tcp/*/get_http" );
if(COMMAND_LINE){
	port = http_get_port( default: 443 );
	soc = http_open_socket( port );
	if(!soc){
		exit( 0 );
	}
	req = create_http_req( port: port, httpver: "10" );
	send( socket: soc, data: req );
	banner = recv( socket: soc, length: 65535 );
	http_close_socket( soc );
	if(!banner || IsMatchRegexp( banner, "^HTTP/1\\.[01] 30[0-8]" ) || IsMatchRegexp( banner, "^HTTP/1\\.[01] 400" )){
		req = create_http_req( port: port, httpver: "11" );
		soc = http_open_socket( port );
		if(soc){
			send( socket: soc, data: req );
			_banner = recv( socket: soc, length: 65535 );
			http_close_socket( soc );
			if(_banner){
				banner = _banner;
			}
		}
	}
	if(!banner){
		exit( 0 );
	}
	banners = make_array( port, banner );
}
if(isnull( banners )){
	exit( 0 );
}
for p in keys( banners ) {
	port = ereg_replace( string: p, pattern: ".*/([0-9]+)/.*", replace: "\\1" );
	port = int( port );
	if(!port || port <= 0 || port > 65535){
		continue;
	}
	if(get_port_transport( port ) > ENCAPS_IP){
		continue;
	}
	b = banners[p];
	if(IsMatchRegexp( b, "<!DOCTYPE HTML .*You're speaking plain HTTP to an SSL-enabled server" ) || ( ContainsString( b, "Bad Request" ) && ContainsString( b, "<pre>This web server is running in SSL mode" ) ) || ContainsString( b, "<p>This web server is running in SSL mode. Try the URL" ) || ContainsString( b, "<h2>HTTPS is required</h2>" ) || ContainsString( b, "This is an SSL protected page, please use the HTTPS scheme instead of the plain HTTP scheme to access this URL." ) || ContainsString( b, "<title>400 The plain HTTP request was sent to HTTPS port</title>" ) || ContainsString( b, "<center>The plain HTTP request was sent to HTTPS port</center>" ) || IsMatchRegexp( hexstr( b ), "^15030[0-3]0002020a$" ) || ( ( ContainsString( b, "Bad Request" ) || IsMatchRegexp( b, "^HTTP/1\\.[01] 400" ) ) && ContainsString( b, "This combination of host and port requires TLS." ) ) || ( IsMatchRegexp( b, "^HTTP/1\\.[01] 400" ) && ContainsString( b, "Client sent an HTTP request to an HTTPS server." ) )){
		log_message( port: port );
		if(COMMAND_LINE){
			display( "\\n **** SSL/TLS server detected on ", get_host_ip(), ":", port, " ****\\n\\n" );
		}
		if(service_is_unknown( port: port )){
			service_register( port: port, proto: "www" );
		}
		for(t = ENCAPS_SSLv2;t < ENCAPS_MAX;t++){
			s = open_sock_tcp( port: port, transport: t );
			if(!s){
				continue;
			}
			req = create_http_req( port: port, httpver: "10" );
			send( socket: s, data: req );
			b = http_recv_headers2( socket: s );
			http_close_socket( s );
			if(!b || IsMatchRegexp( b, "^HTTP/1\\.[01] 30[0-8]" ) || IsMatchRegexp( b, "^HTTP/1\\.[01] 400" )){
				s = open_sock_tcp( port: port, transport: t );
				if(s){
					req = create_http_req( port: port, httpver: "11" );
					send( socket: s, data: req );
					_b = http_recv_headers2( socket: s );
					http_close_socket( s );
					if(_b){
						b = _b;
					}
				}
			}
			replace_kb_item( name: "Transports/TCP/" + port, value: t );
			replace_kb_item( name: "Transport/SSL", value: port );
			if(b){
				replace_kb_item( name: "FindService/tcp/" + port + "/get_http", value: b );
				if(IsMatchRegexp( b, "^HTTP/1\\.[01] [0-9]+" )){
					replace_kb_item( name: "www/banner/" + port + "/", value: b );
				}
			}
			break;
		}
	}
}
exit( 0 );

