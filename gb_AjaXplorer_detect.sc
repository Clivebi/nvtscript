if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100573" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-13 13:16:59 +0200 (Tue, 13 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "AjaXplorer Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running AjaXplorer, a file explorer
  for remotely managing files on a web server." );
	script_xref( name: "URL", value: "http://www.ajaxplorer.info" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "AjaXplorer Detection";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/filemanager", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/content.php?get_action=display_doc&doc_file=CREDITS" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "AjaXplorer Version", string: buf, icase: FALSE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "AjaXplorer Version ([0-9.]+)", icase: TRUE );
		if( !isnull( version[1] ) ){
			vers = chomp( version[1] );
			register_host_detail( name: "App", value: NASLString( "cpe:/a:ajaxplorer:ajaxplorer:", vers ), desc: SCRIPT_DESC );
		}
		else {
			register_host_detail( name: "App", value: NASLString( "cpe:/a:ajaxplorer:ajaxplorer" ), desc: SCRIPT_DESC );
		}
		set_kb_item( name: NASLString( "www/", port, "/AjaXplorer" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "AjaXplorer/installed", value: TRUE );
		info = NASLString( "AjaXplorer Version '" );
		info += NASLString( vers );
		info += NASLString( "' was detected on the remote host in the following directory(s):\\n\\n" );
		info += NASLString( install, "\\n" );
		log_message( port: port, data: info );
		exit( 0 );
	}
}
exit( 0 );
