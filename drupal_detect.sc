if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100169" );
	script_version( "2020-12-16T09:35:48+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-16 09:35:48 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)" );
	script_name( "Drupal Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of Drupal.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
brokenDr = 0;
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", "/drupal", "/drupal6", "/drupal7", "/cms", http_cgi_dirs( port: port ) ) {
	updaterMatches = 0;
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/update.php", port: port );
	res2 = http_get_cache( item: dir + "/", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 30[12]" ) && egrep( pattern: "ocation: .*update\\.php\\?op=info", string: res, icase: FALSE )){
		path = eregmatch( string: res, pattern: "Location:[ ]*http[s]?://[^/]+([^ \r\n]+)", icase: TRUE );
		if(path[1]){
			res = http_get_cache( item: path[1], port: port );
		}
	}
	if(ContainsString( res, "<title>Access denied | " )){
		updaterMatches++;
	}
	if(ContainsString( res, "<meta name=\"Generator\" content=\"Drupal" )){
		updaterMatches++;
	}
	if(ContainsString( res, "<meta name=\"generator\" content=\"Drupal" )){
		updaterMatches++;
	}
	if(ContainsString( res, "$update_free_access = TRUE;" )){
		updaterMatches++;
	}
	if(ContainsString( res, "$update_free_access = FALSE;" )){
		updaterMatches++;
	}
	if(ContainsString( res, "/modules/system/system.css" )){
		updaterMatches++;
	}
	if(ContainsString( res, "From the main Drupal directory that you installed all the files into" )){
		updaterMatches++;
	}
	if(ContainsString( res, "/sites/default/files/logo.png" )){
		updaterMatches++;
	}
	if(ContainsString( res, "/misc/drupal.js?" )){
		updaterMatches++;
	}
	if(updaterMatches > 3 || ContainsString( res2, "<meta name=\"Generator\" content=\"Drupal" ) || ContainsString( res2, "<meta name=\"generator\" content=\"Drupal" ) || ContainsString( res2, "/misc/drupal.js?" ) || ContainsString( res2, "jQuery.extend(Drupal.settings" )){
		if(dir == ""){
			rootInstalled = TRUE;
		}
		version = "unknown";
		if(egrep( pattern: "Access denied for user", string: res, icase: TRUE )){
			brokenDr++;
		}
		if(brokenDr > 1){
			break;
		}
		url = dir + "/CHANGELOG.txt";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		ver = eregmatch( pattern: "Drupal ([0-9.]+), [0-9]{4}-[0-9]{2}-[0-9]{2}", string: res, icase: TRUE );
		if(!isnull( ver[1] )){
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			version = chomp( ver[1] );
		}
		if(version == "unknown"){
			url = dir + "/core/CHANGELOG.txt";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			ver = eregmatch( pattern: "Drupal ([0-9.]+), [0-9]{4}-[0-9]{2}-[0-9]{2}", string: res, icase: TRUE );
			if(!isnull( ver[1] )){
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				version = chomp( ver[1] );
			}
		}
		if(version == "unknown"){
			url = dir + "/core/modules/config/config.info.yml";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			ver = eregmatch( pattern: "version: '([0-9.]+)'", string: res, icase: TRUE );
			if(!isnull( ver[1] )){
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				version = chomp( ver[1] );
			}
		}
		if(version == "unknown"){
			url = dir + "/composer.json";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			ver = eregmatch( pattern: "\"drupal/core\": ?\"(\\~|\\^)([0-9.]+)\"", string: res, icase: FALSE );
			if(!isnull( ver[2] )){
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				version = chomp( ver[2] );
			}
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: "<meta name=\"Generator\" content=\"Drupal ([0-9.]+)", string: res2, icase: TRUE );
			if(!isnull( ver[1] )){
				conclUrl = http_report_vuln_url( port: port, url: dir + "/", url_only: TRUE );
				version = chomp( ver[1] );
			}
		}
		tmp_ver = version + " under " + install;
		set_kb_item( name: "www/" + port + "/drupal", value: tmp_ver );
		set_kb_item( name: "drupal/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:drupal:drupal:" );
		if(!cpe){
			cpe = "cpe:/a:drupal:drupal";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Drupal", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

