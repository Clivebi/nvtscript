if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103106" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-04 13:25:07 +0100 (Fri, 04 Mar 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "phpWebSite Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running phpWebSite. phpWebSite provides a complete web
site content management system." );
	script_xref( name: "URL", value: "http://phpwebsite.appstate.edu/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/phpwebsite", "/cms", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/index.php?module=users&action=user&command=login_page" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "<meta name=\"generator\" content=\"phpWebSite\" />" ) && ContainsString( buf, "User_Login_Main_phpws_username" )){
		vers = NASLString( "unknown" );
		set_kb_item( name: NASLString( "www/", port, "/phpWebSite" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "phpwebsite/detected", value: TRUE );
		info = NASLString( "phpWebSite Version '" );
		info += NASLString( vers );
		info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
		info += NASLString( install, "\\n" );
		log_message( port: port, data: info );
		exit( 0 );
	}
}
exit( 0 );

