if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807499" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-18 12:26:14 +0530 (Fri, 18 Mar 2016)" );
	script_name( "Kaltura Video Platform Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of installed version
  of Kaltura Video Platform.

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
for dir in nasl_make_list_unique( "/", "/Kaltura", "/kvd", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/start/index.php", port: port );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( rcvRes, "title>Kaltura Video Platf(ro|or)m" )){
		version = "unknown";
		edition = "";
		ver = eregmatch( pattern: "Community Edition (Kaltura Server )?([0-9.-]+)", string: rcvRes );
		if( !isnull( ver[2] ) ){
			version = ver[2];
			set_kb_item( name: "kaltura/version", value: version );
			set_kb_item( name: "kaltura/community/installed", value: TRUE );
			edition = "Community ";
		}
		else {
			ver = eregmatch( pattern: "OnPrem.* ([0-9.-]+).</h1>", string: rcvRes );
			if(!isnull( ver[1] )){
				version = ver[1];
				set_kb_item( name: "kaltura/version", value: version );
				set_kb_item( name: "kaltura/onprem/installed", value: TRUE );
				edition = "On-Prem ";
			}
		}
		set_kb_item( name: "kaltura/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.-]+)", base: "cpe:/a:kaltura:kaltura:" );
		if(!cpe){
			cpe = "cpe:/a:kaltura:kaltura";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Kaltura " + edition + "Edition", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

