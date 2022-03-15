if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900182" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)" );
	script_name( "WordPress Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  WordPress/WordPress-Mu.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
rootInstalled = FALSE;
checkduplicate = "";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/blog", "/wordpress", "/wordpress-mu", http_cgi_dirs( port: port ) ) {
	if(rootInstalled){
		break;
	}
	wpFound = FALSE;
	wpMuFound = FALSE;
	version = NULL;
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for file in make_list( "/",
		 "/index.php" ) {
		url = dir + file;
		res = http_get_cache( item: url, port: port );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<meta name=\"generator\" content=\"WordPress" ) || IsMatchRegexp( res, "/wp-content/(plugins|themes|uploads)/" ) || IsMatchRegexp( res, "/wp-includes/(wlwmanifest|js/)" ) )){
			if(dir == ""){
				rootInstalled = TRUE;
			}
			version = "unknown";
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			vers = eregmatch( pattern: "WordPress ([0-9]\\.[0-9.]+)", string: res );
			if(vers[1]){
				version = vers[1];
				if(ContainsString( checkduplicate, version + ", " )){
					continue;
				}
				checkduplicate += version + ", ";
			}
			if(ContainsString( res, "WordPress Mu" )){
				wpMuFound = TRUE;
			}
			if(!ContainsString( res, "WordPress Mu" )){
				wpFound = TRUE;
			}
		}
	}
	if(( !wpMuFound && !wpFound ) || version == "unknown"){
		url = dir + "/wp-links-opml.php";
		req = http_get_req( url: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<!-- generator=\"WordPress" )){
			if(dir == ""){
				rootInstalled = TRUE;
			}
			wpFound = TRUE;
			version = "unknown";
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			vers = eregmatch( pattern: "<!-- generator=\"WordPress/([0-9.]+)", string: res );
			if(vers[1]){
				version = vers[1];
				if(ContainsString( checkduplicate, version + ", " )){
					continue;
				}
				checkduplicate += version + ", ";
			}
		}
	}
	if(( !wpMuFound && !wpFound ) || version == "unknown"){
		url = dir + "/feed/";
		res = http_get_cache( item: url, port: port );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<generator>http://wordpress.org/" )){
			if(dir == ""){
				rootInstalled = TRUE;
			}
			wpFound = TRUE;
			version = "unknown";
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			vers = eregmatch( pattern: "v=([0-9.]+)</generator>", string: res );
			if(vers[1]){
				version = vers[1];
				if(ContainsString( checkduplicate, version + ", " )){
					continue;
				}
				checkduplicate += version + ", ";
			}
		}
	}
	if(( !wpMuFound && !wpFound ) || version == "unknown"){
		url = dir + "/wp-login.php";
		req = http_get_req( url: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "/wp-login.php?action=lostpassword" ) || ContainsString( res, "/wp-admin/load-" ) || IsMatchRegexp( res, "/wp-content/(plugins|themes|uploads)/" ) )){
			if(dir == ""){
				rootInstalled = TRUE;
			}
			wpFound = TRUE;
			version = "unknown";
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			vers = eregmatch( pattern: "ver=([0-9.]+)", string: res );
			if(vers[1]){
				version = vers[1];
				if(ContainsString( checkduplicate, version + ", " )){
					continue;
				}
				checkduplicate += version + ", ";
			}
		}
	}
	if(( !wpMuFound && !wpFound ) || version == "unknown"){
		url = dir + "/readme.html";
		res = http_get_cache( item: url, port: port );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "<title>WordPress.*ReadMe</title>" )){
			if(dir == ""){
				rootInstalled = TRUE;
			}
			wpFound = TRUE;
			version = "unknown";
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			vers = eregmatch( pattern: "<br />.*Version ([0-9.]+).*</h1>", string: res );
			if(vers[1]){
				version = vers[1];
				if(ContainsString( checkduplicate, version + ", " )){
					continue;
				}
				checkduplicate += version + ", ";
			}
		}
	}
	if( wpMuFound ){
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/WordPress-Mu", value: tmp_version );
		set_kb_item( name: "wordpress/installed", value: TRUE );
		register_and_report_cpe( app: "WordPress-Mu", ver: version, conclUrl: conclUrl, concluded: vers[0], base: "cpe:/a:wordpress:wordpress_mu:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www" );
	}
	else {
		if(wpFound){
			tmp_version = version + " under " + install;
			set_kb_item( name: "www/" + port + "/WordPress", value: tmp_version );
			set_kb_item( name: "wordpress/installed", value: TRUE );
			register_and_report_cpe( app: "WordPress", ver: version, conclUrl: conclUrl, concluded: vers[0], base: "cpe:/a:wordpress:wordpress:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www" );
		}
	}
}
exit( 0 );

