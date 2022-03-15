if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100300" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Thin Webserver Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 3000 );
	script_mandatory_keys( "thin/banner" );
	script_tag( name: "summary", value: "This host is running Thin, a Ruby web server." );
	script_xref( name: "URL", value: "http://code.macournoyer.com/thin/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 3000 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: thin" )){
	exit( 0 );
}
vers = NASLString( "unknown" );
version = eregmatch( string: banner, pattern: "Server: thin ([0-9.]+)", icase: TRUE );
if(!isnull( version[1] )){
	vers = chomp( version[1] );
}
set_kb_item( name: NASLString( "www/", port, "/thin" ), value: NASLString( vers ) );
info = NASLString( "Thin Version '" );
info += NASLString( vers );
info += NASLString( "' was detected on the remote host\\n" );
log_message( port: port, data: info );
exit( 0 );

