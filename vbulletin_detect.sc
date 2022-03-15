if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17282" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "vBulletin Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.vbulletin.com/" );
	script_tag( name: "summary", value: "Detects the installed version of vBulletin discussion forum.

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
for dir in nasl_make_list_unique( "/", "/forum", "/vbulletin", "/vbulletin/forum", http_cgi_dirs( port: port ) ) {
	for file in make_list( "/index.php",
		 "/content.php" ) {
		install = dir;
		if(dir == "/"){
			dir = "";
		}
		res = http_get_cache( item: dir + file, port: port );
		if(!res){
			continue;
		}
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "( content=.vBulletin |alt=\"Logo\" title=\"Powered by vBulletin\"|id=\"footer-vb-copyright\">Powered by.+vBulletin|<meta name=\"generator\" content=\"vBulletin)", string: res, icase: TRUE )){
			version = "unknown";
			ver = eregmatch( pattern: "<meta name=\"generator\" content=\"vBulletin ([0-9.]+)", string: res );
			if(isnull( ver[1] )){
				_ver = egrep( pattern: "Powered by.*vBulletin.*Version ([0-9.]+)", string: res );
				if(_ver){
					ver = eregmatch( pattern: "Powered by.*vBulletin.*Version ([0-9.]+)", string: _ver );
				}
			}
			if(isnull( ver[1] )){
				ver = eregmatch( pattern: "vBulletin ([0-9.]+)", string: res, icase: TRUE );
			}
			if(!isnull( ver[1] )){
				version = ver[1];
			}
			set_kb_item( name: "vbulletin/detected", value: TRUE );
			set_kb_item( name: "www/can_host_tapatalk", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:vbulletin:vbulletin:" );
			if(!cpe){
				cpe = "cpe:/a:vbulletin:vbulletin";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "vBulletin", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
			break;
		}
	}
}
exit( 0 );

