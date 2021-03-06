if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140443" );
	script_version( "2020-11-27T13:21:49+0000" );
	script_tag( name: "last_modification", value: "2020-11-27 13:21:49 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-10-20 10:51:43 +0700 (Fri, 20 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ILIAS Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of ILIAS eLearning." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.ilias.de" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/ilias", "/ILIAS", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/setup/setup.php";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	loc = http_extract_location_from_redirect( port: port, data: res, current_dir: install );
	if(isnull( loc )){
		continue;
	}
	cookie = http_get_cookie_from_header( buf: res, pattern: "Set-Cookie: (SESSID=[0-9A-Za-z]+);" );
	if(!cookie){
		cookie = "SESSID=" + rand_str( length: 32, charset: "abcdefghijklmnopqrstuvwxyz0123456789" );
	}
	req = http_get_req( port: port, url: loc, add_headers: make_array( "Cookie", cookie ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(( IsMatchRegexp( res, "<title>ILIAS ([0-9] )?Setup</title>" ) || ContainsString( res, "<title>ILIAS Setup</title>" ) ) && ( ContainsString( res, "std setup ilSetupLogin" ) || ContainsString( res, "class=\"ilSetupLogin\">" ) || ContainsString( res, "class=\"ilLogin\">" ) || ContainsString( res, "class=\"il_Header\">" ) )){
		version = "unknown";
		vers = eregmatch( pattern: "(class=\"row\">|<small>)ILIAS ([0-9.]+)", string: res );
		if( !isnull( vers[2] ) ){
			version = vers[2];
		}
		else {
			url = "/login.php?lang=en";
			req = http_get( port: port, item: url );
			res = http_keepalive_send_recv( port: port, data: req );
			vers = eregmatch( pattern: ">powered by <b>ILIAS</b> \\(v([0-9.]+)", string: res );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
		set_kb_item( name: "ilias/version", value: version );
		set_kb_item( name: "ilias/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ilias:ilias:" );
		if(!cpe){
			cpe = "cpe:/a:ilias:ilias";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "ILIAS", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) ), port: port );
		exit( 0 );
	}
}
exit( 0 );

