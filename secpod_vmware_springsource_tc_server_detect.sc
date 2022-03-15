if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902187" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Vmware SpringSource tc Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Vmware SpringSource tc
  Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/myserver", "/SStc", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.html", port: port );
	if(ContainsString( rcvRes, "<title>SpringSource tc Server</title>" )){
		version = "unknown";
		sndReq = http_get( item: dir + "/WEB-INFO/web.xml", port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		if(ContainsString( rcvRes, "SpringSource tc Server runtime" )){
			ver = eregmatch( pattern: "tc Server runtime/(([0-9.]+).?([A-Za-z0-9-]+))?", string: rcvRes );
			ver = ereg_replace( pattern: "-", replace: ".", string: ver[1] );
			if(ver != NULL){
				version = ver;
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/Vmware/SSTC/Runtime", value: tmp_version );
		set_kb_item( name: "vmware/tc_server/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:tc_server:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:vmware:tc_server";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SpringSource tc Server", version: version, install: install, cpe: cpe, concluded: ver ), port: port );
	}
}
exit( 0 );

