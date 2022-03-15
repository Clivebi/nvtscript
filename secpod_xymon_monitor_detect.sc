if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902503" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Xymon Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Xymon

  The script sends a connection request to the server and attempts to detect Xymon and to extract its
  version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://xymon.sourceforge.net/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/xymon", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/xymon.html", port: port );
	if(IsMatchRegexp( res, "^HTTP/1.[01] 200" ) && ContainsString( res, ">Xymon<" )){
		version = "unknown";
		ver = eregmatch( pattern: ">Xymon ([0-9.]+)<", string: res );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		set_kb_item( name: "xymon/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:xymon:xymon:" );
		if(!cpe){
			cpe = "cpe:/a:xymon:xymon";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Xymon", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

