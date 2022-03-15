if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11720" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "S-HTTP detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This web server supports S-HTTP, a cryptographic layer
  that was defined in 1999 by RFC 2660.

  S-HTTP has never been widely implemented and you should
  use HTTPS instead.

  As rare or obsolete code is often badly tested, it would be
  safer to use another server or disable this layer somehow." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "Secure * Secure-HTTP/1.4\\r\\n", "Host: ", host, "\\r\\n", "Connection: close\\r\\n", "\\r\\n" );
send( socket: soc, data: req );
r = recv_line( socket: soc, length: 256 );
http_close_socket( soc );
if(ereg( pattern: "Secure-HTTP/[0-9]\\.[0-9] 200", string: r )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

