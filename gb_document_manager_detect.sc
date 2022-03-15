if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800477" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Document Manager Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running Document Manager version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
dmPort = http_get_port( default: 80 );
if(!http_can_host_php( port: dmPort )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/", "/dmanager", http_cgi_dirs( port: dmPort ) ) {
	install = path;
	if(path == "/"){
		path = "";
	}
	sndReq = http_get( item: path + "/php/login.php", port: dmPort );
	rcvRes = http_keepalive_send_recv( port: dmPort, data: sndReq );
	if(ContainsString( rcvRes, "Document Manager" ) || ContainsString( rcvRes, "Porte Documents" )){
		version = "unknown";
		dmVer = eregmatch( pattern: "version ([0-9.]+)", string: rcvRes );
		if( dmVer[1] != NULL ){
			version = dmVer[1];
		}
		else {
			sndReq = http_get( item: path + "/php/version", port: dmPort );
			rcvRes = http_keepalive_send_recv( port: dmPort, data: sndReq, bodyonly: 1 );
			if(!isnull( rcvRes )){
				dmVer = eregmatch( pattern: "([0-9.]+)", string: rcvRes );
				if(dmVer[1] != NULL){
					version = dmVer[1];
				}
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + dmPort + "/DocManager", value: tmp_version );
		set_kb_item( name: "docmanager/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:dmanager:documentmanager:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:dmanager:documentmanager";
		}
		register_product( cpe: cpe, location: install, port: dmPort, service: "www" );
		log_message( data: build_detection_report( app: "Document Manager", version: version, install: install, cpe: cpe, concluded: dmVer[0] ), port: dmPort );
	}
}

