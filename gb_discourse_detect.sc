if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108454" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-04 23:29:30 +0200 (Sat, 04 Aug 2018)" );
	script_name( "Discourse Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.discourse.org/" );
	script_tag( name: "summary", value: "Detection of Discourse.

  The script sends a connection request to the server and attempts to
  identify an installed Discourse software from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/forum", "/forums", "/community", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/", port: port );
	buf2 = http_get_cache( item: dir + "/login", port: port );
	if(( IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<meta name=\"discourse_theme_key\"" ) || ContainsString( buf, "<meta name=\"discourse_theme_id\"" ) || ContainsString( buf, "<meta name=\"discourse_current_homepage\"" ) || ContainsString( buf, "<meta name=\"generator\" content=\"Discourse" ) || ContainsString( buf, "<p>Powered by <a href=\"https://www.discourse.org\">Discourse</a>" ) || ContainsString( buf, "<script>Discourse._registerPluginCode" ) || ContainsString( buf, "Discourse.start();" ) ) ) || ( IsMatchRegexp( buf, "^HTTP/1\\.[01] 500" ) && ContainsString( buf, "<title>Oops - Error 500</title>" ) && ContainsString( buf, "<h1>Oops</h1>" ) && ContainsString( buf, "<p>The software powering this discussion forum encountered an unexpected problem. We apologize for the inconvenience.</p>" ) ) || ( IsMatchRegexp( buf2, "^HTTP/1\\.[01] 200" ) && ContainsString( buf2, "<meta name=\"generator\" content=\"Discourse" ) )){
		version = "unknown";
		cpe = "cpe:/a:discourse:discourse";
		set_kb_item( name: "discourse/detected", value: TRUE );
		vers = eregmatch( string: buf, pattern: "content=\"Discourse ([0-9.]+)(\\.beta[0-9]+)?" );
		if( vers[1] && vers[2] ){
			version = vers[1] + vers[2];
			cpe += ":" + version;
		}
		else {
			if( vers[1] ){
				version = vers[1];
				cpe += ":" + version;
			}
			else {
				vers = eregmatch( string: buf2, pattern: "content=\"Discourse ([0-9.]+)(\\.beta[0-9]+)?" );
				if( vers[1] && vers[2] ){
					version = vers[1] + vers[2];
					cpe += ":" + version;
				}
				else {
					if(vers[1]){
						version = vers[1];
						cpe += ":" + version;
					}
				}
			}
		}
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 500" )){
			extra = "The Discourse software is currently in a not working state and is reporting an internal server error.";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Discourse", version: version, install: install, cpe: cpe, concluded: vers[0], extra: extra ), port: port );
		exit( 0 );
	}
}
exit( 0 );

