if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800818" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DM FileManager Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of DM FileManager and
  DM Albums." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir1 in nasl_make_list_unique( "/dm-filemanager", "/dmf", "/", http_cgi_dirs( port: port ) ) {
	install1 = dir1;
	if(dir1 == "/"){
		dir1 = "";
	}
	rcvRes1 = http_get_cache( item: dir1 + "/login.php", port: port );
	if(IsMatchRegexp( rcvRes1, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes1, "<title>Log In - DM FileManager" )){
		version1 = "unknown";
		ver1 = eregmatch( pattern: "DM FileManager[^?]+v([0-9]\\.[0-9.]+)", string: rcvRes1 );
		if(ver1[1] != NULL){
			version1 = ver1[1];
		}
		set_kb_item( name: "dm-filemanager/detected", value: TRUE );
		cpe1 = build_cpe( value: version1, exp: "^([0-9.]+)", base: "cpe:/a:dutchmonkey:dm_filemanager:" );
		if(isnull( cpe1 )){
			cpe1 = "cpe:/a:dutchmonkey:dm_filemanager";
		}
		register_and_report_cpe( app: "DM FileManager", ver: version1, concluded: ver1[0], cpename: cpe1, insloc: install1, regPort: port );
		for dir2 in make_list( "/dm-albums",
			 "/albums" ) {
			install2 = dir1 + dir2;
			sndReq2 = http_get( item: dir1 + dir2 + "/readme.txt", port: port );
			rcvRes2 = http_keepalive_send_recv( data: sndReq2, port: port );
			if(IsMatchRegexp( rcvRes2, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes2, "DM Albums" )){
				version2 = "unknown";
				ver2 = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: rcvRes2 );
				if(ver2[1] != NULL){
					version2 = ver2[1];
				}
				cpe2 = build_cpe( value: version2, exp: "^([0-9.]+)", base: "cpe:/a:dutchmonkey:dm_album:" );
				if(isnull( cpe2 )){
					cpe2 = "cpe:/a:dutchmonkey:dm_album";
				}
				register_and_report_cpe( app: "DM Albums", ver: version2, concluded: ver2[0], cpename: cpe2, insloc: install2, regPort: port );
			}
		}
	}
}
exit( 0 );

