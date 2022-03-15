if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100219" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-06-14 17:19:03 +0200 (Sun, 14 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "phpWebThings Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running phpWebThings a free, PHP and MySQL driven
  Content Management System." );
	script_xref( name: "URL", value: "http://www.phpwebthings.nl/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
SCRIPT_DESC = "phpWebThings Detection";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/cms", "/phpwebthings", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "meta.*content=\"phpWebThings\"", string: buf, icase: TRUE ) || egrep( pattern: "This website was created with <a [^>]+>phpWebThings \"", string: buf, icase: TRUE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "phpWebThings ([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		tmp_version = NASLString( vers, " under ", install );
		set_kb_item( name: NASLString( "www/", port, "/phpWebThings" ), value: tmp_version );
		set_kb_item( name: "phpwebthings/detected", value: TRUE );
		cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+)", base: "cpe:/a:phpwebthings:phpwebthings:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		info = NASLString( "phpWebThings Version '" );
		info += NASLString( vers );
		info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
		info += NASLString( install, "\\n" );
		log_message( port: port, data: info );
		exit( 0 );
	}
}
exit( 0 );

