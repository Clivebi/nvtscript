if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808087" );
	script_version( "2021-01-18T08:23:14+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-18 08:23:14 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-06-21 12:44:48 +0530 (Tue, 21 Jun 2016)" );
	script_name( "Elastic Kibana/X-Pack Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 5601 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Elastic Kibana and X-Pack." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 5601 );
for dir in nasl_make_list_unique( "/", "/kibana", http_cgi_dirs( port: port ) ) {
	if(ContainsString( dir, "/app/kibana" ) || ContainsString( dir, "/app/ui" )){
		continue;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/app/kibana";
	res = http_get_cache( item: url, port: port );
	url2 = dir + "/";
	res2 = http_get_cache( item: url2, port: port );
	if(( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( egrep( string: res, pattern: "^kbn-(name|version|license-sig|xpack-sig): ", icase: TRUE ) || ContainsString( res, "<title>Kibana</title>" ) || ContainsString( res, "x-app-name: kibana" ) ) ) || ( IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ( egrep( string: res2, pattern: "^X-App-Name: kibana", icase: TRUE ) || IsMatchRegexp( res2, "<title>Kibana [34{<]{2}" ) ) )){
		version = "unknown";
		vers = eregmatch( pattern: "kbn-version: ([0-9.]+)", string: res );
		if(vers[1]){
			version = vers[1];
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "x-app-version: ([0-9.]+)", string: res );
			if(vers[1]){
				version = vers[1];
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "version(&quot;|\"):(&quot;|\")([0-9.]+)", string: res );
			if(vers[3]){
				version = vers[3];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "window\\.KIBANA_VERSION='([0-9.]+)';", string: res2 );
			if(vers[1]){
				version = vers[1];
			}
		}
		if(version == "unknown"){
			vers_url = url2 + "app/components/require.config.js";
			vers_res = http_get_cache( item: vers_url, port: port );
			vers = eregmatch( pattern: "/\\*! kibana - v([0-9.]+)(milestone([0-9]))? -", string: vers_res );
			if(vers[1]){
				version = vers[1];
				if(vers[3]){
					set_kb_item( name: "elastic/kibana/milestone", value: vers[3] );
				}
				conclUrl = http_report_vuln_url( port: port, url: vers_url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "<title>Kibana ([0-9])", string: res2 );
			if(vers[1]){
				version = vers[1];
			}
		}
		set_kb_item( name: "elastic/kibana/detected", value: TRUE );
		register_and_report_cpe( app: "Elastic Kibana", ver: version, base: "cpe:/a:elastic:kibana:", expr: "^([0-9.]+)", concluded: vers[0], insloc: install, conclUrl: conclUrl, regPort: port, regService: "www" );
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && egrep( string: res, pattern: "^kbn-(name|version|license-sig|xpack-sig): ", icase: TRUE ) && IsMatchRegexp( res, "location: .*/login\\?next(Url)?=%2F.*app%2Fkibana" )){
		version = "unknown";
		set_kb_item( name: "elastic/kibana/detected", value: TRUE );
		set_kb_item( name: "elastic/kibana/x-pack/detected", value: TRUE );
		vers = eregmatch( pattern: "kbn-version: ([0-9.]+)", string: res );
		if(vers[1]){
			version = vers[1];
		}
		if(version == "unknown"){
			redirect = http_extract_location_from_redirect( port: port, data: res, current_dir: install );
			if(redirect){
				res = http_get_cache( item: redirect, port: port );
				if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
					vers = eregmatch( pattern: "version(&quot;|\"):(&quot;|\")([0-9.]+)", string: res );
					if(vers[3]){
						version = vers[3];
						conclUrl = http_report_vuln_url( port: port, url: redirect, url_only: TRUE );
					}
				}
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:elastic:kibana:" );
		if(!cpe){
			cpe = "cpe:/a:elastic:kibana";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		report = build_detection_report( app: "Elastic Kibana", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:elastic:x-pack:" );
		if(!cpe){
			cpe = "cpe:/a:elastic:x-pack";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		report += "\n\n";
		report += build_detection_report( app: "Elastic X-Pack", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0], extra: "Note: The X-Pack version is always matching the Kibana version" );
		log_message( port: port, data: report );
		exit( 0 );
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 503" ) && concl = egrep( string: res, pattern: "^Kibana server is not ready yet", icase: FALSE )){
		set_kb_item( name: "elastic/kibana/detected", value: TRUE );
		register_and_report_cpe( app: "Elastic Kibana", ver: "unknown", cpename: "cpe:/a:elastic:kibana", concluded: "HTTP/1.1 503\n(truncated)\n" + chomp( concl ), insloc: install, regPort: port, regService: "www" );
		exit( 0 );
	}
}
exit( 0 );

