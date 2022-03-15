if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146229" );
	script_version( "2021-07-06T11:21:34+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:21:34 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 08:02:05 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Textpattern CMS Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Textpattern CMS." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://textpattern.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/cms", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res1 = http_get_cache( port: port, item: dir + "/" );
	res2 = http_get_cache( port: port, item: dir + "/index.php" );
	if(ContainsString( res1, "name=\"generator\" content=\"Textpattern CMS\"" ) || ( ContainsString( res2, ">Textpattern<" ) && ContainsString( res2, "Textpattern CMS<" ) )){
		version = "unknown";
		url = dir + "/HISTORY.txt";
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "Changes in ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			url = dir + "/README.txt";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req );
			vers = eregmatch( pattern: "Textpattern (CMS )?([0-9.]+)", string: res );
			if(!isnull( vers[2] )){
				version = vers[2];
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		set_kb_item( name: "textpattern_cms/detected", value: TRUE );
		set_kb_item( name: "textpattern_cms/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:textpattern:textpattern:" );
		if(!cpe){
			cpe = "cpe:/a:textpattern:textpattern";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Textpattern CMS", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

