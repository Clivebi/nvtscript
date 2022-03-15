if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107216" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Composr CMS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of Composr CMS.

  The script tries to detect Composr CMS via HTTP request and to extract its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
appPort = http_get_port( default: 80 );
if(!http_can_host_php( port: appPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: appPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php?page=start";
	rcvRes = http_get_cache( item: url, port: appPort );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Powered by Composr" )){
		Ver = "unknown";
		tmpVer = eregmatch( pattern: "Powered by Composr version ([0-9.]+),", string: rcvRes );
		if(!tmpVer){
			tmpVer = eregmatch( pattern: "Powered by Composr version ([0-9.]+) ([A-Z]+[0-9]+),", string: rcvRes );
		}
		if(tmpVer[1]){
			Ver = tmpVer[1];
			if(tmpVer[2]){
				Ver += " " + tmpVer[2];
			}
		}
		set_kb_item( name: "composr_cms/installed", value: TRUE );
		cpe = build_cpe( value: Ver, exp: "^([0-9.]+)", base: "cpe:/a:composr:cms:" );
		if(cpe && tmpVer[2]){
			cpe += tmpVer[2];
		}
		if(!cpe){
			cpe = "cpe:/a:composr:cms";
		}
		register_product( cpe: cpe, location: install, port: appPort, service: "www" );
		log_message( data: build_detection_report( app: "Composr_CMS", version: Ver, install: install, cpe: cpe, concluded: tmpVer[0] ), port: appPort );
	}
}
exit( 0 );

