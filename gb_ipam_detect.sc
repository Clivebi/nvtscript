if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107046" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-09-12 13:18:59 +0200 (Mon, 12 Sep 2016)" );
	script_name( "phpIPAM Web Application Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of phpIPAM Web Application" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
http_port = http_get_port( default: 80 );
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", "/phpipam", http_cgi_dirs( port: http_port ) ) {
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/?page=login";
	req = http_get( item: url, port: http_port );
	buf = http_keepalive_send_recv( port: http_port, data: req );
	if(isnull( buf )){
		continue;
	}
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "phpIPAM IP address management" )){
		if(dir == ""){
			rootInstalled = TRUE;
		}
		vers = "unknown";
		version = eregmatch( pattern: "phpIPAM IP address management \\[v([0-9.]+)\\]( rev([0-9]+))?", string: buf );
		if( version[1] && version[3] ){
			vers = version[1] + "." + version[3];
		}
		else {
			if(version[1]){
				vers = version[1];
			}
		}
		set_kb_item( name: "phpipam/" + http_port + "/version", value: vers );
		set_kb_item( name: "phpipam/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:phpipam:phpipam:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:phpipam:phpipam";
		}
		register_product( cpe: cpe, location: install, port: http_port, service: "www" );
		log_message( data: build_detection_report( app: "phpIPAM", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: http_port );
	}
}
exit( 0 );

