if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103152" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-05-02 15:13:22 +0200 (Mon, 02 May 2011)" );
	script_name( "Atlassian Confluence Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Atlassian Confluence.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
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
for dir in nasl_make_list_unique( "/", "/confluence", "/wiki", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.action";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(( egrep( pattern: "Powered by <a[^>]+>Atlassian Confluence", string: buf, icase: TRUE ) && egrep( pattern: "<form.*name=\"loginform\" method=\"POST\" action=\"[^\"]*/dologin.action\"", string: buf, icase: TRUE ) ) || ContainsString( buf, "<title>Log In - Confluence" )){
		version = "unknown";
		extra = "";
		if(!vers = eregmatch( string: buf, pattern: "Atlassian Confluence</a>.*>([0-9.]+)", icase: TRUE )){
			vers = eregmatch( string: buf, pattern: "<meta name=\"ajs-version-number\" content=\"([0-9.]+)\">", icase: TRUE );
		}
		if(vers[1]){
			version = vers[1];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		build_info = eregmatch( pattern: "<meta name=\"ajs-build-number\" content=\"([0-9]+)\">", string: buf, icase: TRUE );
		if(build_info[1]){
			extra += "Build: " + build_info[1];
		}
		if(version == "unknown"){
			url = dir + "/rest/applinks/1.0/manifest";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			vers = eregmatch( string: buf, pattern: "<version>([0-9.]+)</version>", icase: TRUE );
			if(vers[1]){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				mp_build_info = eregmatch( pattern: "<buildNumber>([0-9]+)", string: buf, icase: TRUE );
				if(mp_build_info[1]){
					extra += "\nMarketplace Build: " + mp_build_info[1];
				}
			}
		}
		set_kb_item( name: "atlassian/confluence/detected", value: TRUE );
		if(!cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:confluence:" )){
			cpe = "cpe:/a:atlassian:confluence";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Atlassian Confluence", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: conclUrl, extra: extra ), port: port );
		exit( 0 );
	}
}
exit( 0 );

