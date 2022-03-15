if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900892" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_name( "XOOPS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed XOOPS version.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
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
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", "/xoops", http_cgi_dirs( port: port ) ) {
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	res2 = http_get_cache( item: dir + "/user.php", port: port );
	if(( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "generator\" content=\"XOOPS\" />" ) || ContainsString( res, ">Powered by XOOPS" ) || ContainsString( res, ">The XOOPS Project<" ) || ( ContainsString( res, "/xoops.css" ) && ContainsString( res, "/xoops.js" ) ) ) ) || ( IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "generator\" content=\"XOOPS\" />" ) || ContainsString( res, ">Powered by XOOPS" ) || ContainsString( res, ">The XOOPS Project<" ) || ( ContainsString( res, "/xoops.css" ) && ContainsString( res, "/xoops.js" ) ) ) )){
		version = "unknown";
		conclUrl = NULL;
		if(install == "/"){
			rootInstalled = TRUE;
		}
		url = dir + "/../release_notes.txt";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "XOOPS" ) && ContainsString( res, "version" )){
			ver = eregmatch( pattern: "XOOPS ([0-9]\\.[0-9.]+).?(Final|RC[0-9]|[a-z])?", string: res, icase: TRUE );
			if(!isnull( ver[1] )){
				if( !isnull( ver[2] ) ){
					version = ver[1] + "." + ver[2];
				}
				else {
					version = ver[1];
				}
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			url = dir + "/class/libraries/composer.json";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			ver = eregmatch( pattern: "Libraries for XOOPS ([0-9]\\.[0-9.]+).?(Final|RC[0-9]|[a-z])?", string: res, icase: TRUE );
			if(!isnull( ver[1] )){
				if( !isnull( ver[2] ) ){
					version = ver[1] + "." + ver[2];
				}
				else {
					version = ver[1];
				}
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/XOOPS", value: tmp_version );
		set_kb_item( name: "XOOPS/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?", base: "cpe:/a:xoops:xoops:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:xoops:xoops";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "XOOPS", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

