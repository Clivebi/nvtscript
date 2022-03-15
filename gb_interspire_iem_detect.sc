if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112086" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-18 15:11:22 +0200 (Wed, 18 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Interspire IEM Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This scripts tries to detect the Interspire Email Marketer and its version on the host system." );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/iem", "/IEM", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/index.php";
	res = http_get_cache( port: port, item: url );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<title>Control Panel</title>" ) && ContainsString( res, "<script src=\"includes/js/tiny_mce/tiny_mce.js\"></script>" ) && ContainsString( res, "Cookie: IEMSESSIONID" ) && ( ContainsString( res, "<option value=\"index.php?Page=Stats\">My Campaign Statistics</option>" ) || ContainsString( res, "var UnsubLinkPlaceholder = \"Unsubscribe me from this list\";" ) || ContainsString( res, "$(document.frmLogin.ss_takemeto).val('index.php');" ) || ContainsString( res, "<td style=\"padding:10px 0px 5px 0px\">Login with your username and password below.</td>" ) )){
		set_kb_item( name: "interspire/iem/installed", value: TRUE );
		version = "unknown";
		if(ver = eregmatch( pattern: "Powered by.* ([0-9.]+)</a>", string: res, icase: TRUE )){
			version = ver[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			set_kb_item( name: "interspire/iem/version", value: version );
			set_kb_item( name: "www/" + port + "/iem", value: version + " under " + install );
		}
		if(!cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:interspire:iem:" )){
			cpe = "cpe:/a:interspire:iem";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Interspire Email Marketer", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

