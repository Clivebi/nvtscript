if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801575" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Hastymail2 Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script detects the version of Hastymail2 on remote host
  and sets the KB." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/Hastymail2", "/hastymail2", "/hastymail", "/hm2", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( rcvRes, "Login | Hastymail2<" ) && ContainsString( rcvRes, "Hastymail Development Group" )){
		version = "unknown";
		sndReq = http_get( item: dir + "/UPGRADING", port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		ver = eregmatch( pattern: "to (([a-zA-z]+)?([0-9.]+)( (RC[0-9]))?)", string: rcvRes );
		if( ver[1] != NULL && ver[2] != NULL ){
			version = ver[1];
		}
		else {
			if(ver[3] != NULL && ver[2] == NULL){
				version = ver[3];
			}
		}
		if(ContainsString( ver[5], "RC" )){
			version = version + " " + ver[5];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/Hastymail2", value: tmp_version );
		set_kb_item( name: "hastymail2/detected", value: TRUE );
		if( version != "unknown" ){
			cpe = "cpe:/a:hastymail:hastymail2:" + version;
		}
		else {
			cpe = "cpe:/a:hastymail:hastymail2";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Hastymail2", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

