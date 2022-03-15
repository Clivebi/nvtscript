if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100034" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "HTTP-Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "find_service1.sc", "find_service2.sc", "apache_SSL_complain.sc", "sw_ssl_cert_get_hostname.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Check the HTTP-Version" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
func set_http_ver_nd_exit( port, httpver ){
	var port, httpver, _httpver;
	_httpver = get_kb_item( "http/" + port );
	if(!_httpver){
		set_kb_item( name: "http/" + port, value: httpver );
		exit( 0 );
	}
	if(int( httpver ) > int( _httpver )){
		replace_kb_item( name: "http/" + port, value: httpver );
	}
	exit( 0 );
}
port = http_get_port( default: 80 );
host = http_host_name( port: port );
host_plain = http_host_name( dont_add_port: TRUE );
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
useragent = http_get_user_agent();
req = NASLString( "GET / HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: */*\\r\\n", "Connection: close\\r\\n", "\\r\\n" );
send( socket: soc, data: req );
buf = http_recv_headers2( socket: soc );
http_close_socket( soc );
if(isnull( buf ) || buf == ""){
	exit( 0 );
}
if( IsMatchRegexp( buf, "^HTTP/1\\.[01] 50[0-4]" ) ){
	set_kb_item( name: "www/" + host_plain + "/" + port + "/is_broken/", value: TRUE );
	set_kb_item( name: "www/" + host_plain + "/" + port + "/is_broken/reason", value: "50x" );
	exit( 0 );
}
else {
	if( IsMatchRegexp( buf, "^HTTP/1\\.1 [1-5][0-9][0-9]" ) ){
		set_http_ver_nd_exit( port: port, httpver: "11" );
	}
	else {
		if( IsMatchRegexp( buf, "^HTTP/1\\.0 [1-5][0-9][0-9]" ) ){
			set_http_ver_nd_exit( port: port, httpver: "10" );
		}
		else {
			soc = http_open_socket( port );
			if(!soc){
				exit( 0 );
			}
			req = NASLString( "GET / HTTP/1.0\\r\\n", "\\r\\n" );
			send( socket: soc, data: req );
			buf = http_recv_headers2( socket: soc );
			http_close_socket( soc );
			if(isnull( buf ) || buf == ""){
				exit( 0 );
			}
			if( IsMatchRegexp( buf, "^HTTP/1\\.[01] 50[0-4]" ) ){
				set_kb_item( name: "www/" + host_plain + "/" + port + "/is_broken/", value: TRUE );
				set_kb_item( name: "www/" + host_plain + "/" + port + "/is_broken/reason", value: "50x" );
				exit( 0 );
			}
			else {
				if(IsMatchRegexp( buf, "^HTTP/1\\.0 [1-5][0-9][0-9]" )){
					set_http_ver_nd_exit( port: port, httpver: "10" );
				}
			}
		}
	}
}
set_http_ver_nd_exit( port: port, httpver: "10" );

