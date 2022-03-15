if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800821" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "V-webmail Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of V-webmail." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
vwmailPort = http_get_port( default: 80 );
if(!http_can_host_php( port: vwmailPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/v-webmail", "/webmail", http_cgi_dirs( port: vwmailPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/htdocs/login.php", port: vwmailPort );
	rcvRes = http_keepalive_send_recv( data: sndReq, port: vwmailPort );
	if(IsMatchRegexp( rcvRes, "<title>V-webmail [0-9.]+</title>" ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: rcvRes )){
		version = "unknown";
		vwmailVer = eregmatch( pattern: "V-webmail ([0-9]\\.[0-9]\\.[0-9])", string: rcvRes );
		if(vwmailVer[1] != NULL){
			version = vwmailVer[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + vwmailPort + "/V-webmail", value: tmp_version );
		set_kb_item( name: "v-webmail/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:christof_bruyland:v-webmail:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:christof_bruyland:v-webmail";
		}
		register_product( cpe: cpe, location: install, port: vwmailPort, service: "www" );
		log_message( data: build_detection_report( app: "V-webmail", version: version, install: install, cpe: cpe, concluded: vwmailVer[0] ), port: vwmailPort );
	}
}

