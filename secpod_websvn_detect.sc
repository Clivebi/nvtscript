if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900440" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "WebSVN version detection" );
	script_tag( name: "summary", value: "The script detects the version of WebSVN." );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
websvnPort = http_get_port( default: 80 );
if(!http_can_host_php( port: websvnPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/websvn", "/svn", http_cgi_dirs( port: websvnPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: websvnPort );
	if(!ContainsString( rcvRes, "WebSVN" )){
		rcvRes = http_get_cache( item: NASLString( dir, "/listing.php" ), port: websvnPort );
	}
	if(ContainsString( rcvRes, "WebSVN" ) && ContainsString( rcvRes, "Subversion" )){
		svnVer = eregmatch( pattern: "WebSVN ([0-9.]+)", string: rcvRes );
		if( svnVer[1] == NULL ){
			svnVer = "Unknown";
		}
		else {
			svnVer = svnVer[1];
		}
		set_kb_item( name: "WebSVN/Installed", value: TRUE );
		if(svnVer != "Unknown"){
			set_kb_item( name: "www/" + websvnPort + "/WebSVN", value: svnVer );
		}
		register_and_report_cpe( app: "WebSVN", ver: svnVer, concluded: svnVer, base: "cpe:/a:tigris:websvn:", expr: "^([0-9.]+)", insloc: install, regPort: websvnPort );
		exit( 0 );
	}
}

