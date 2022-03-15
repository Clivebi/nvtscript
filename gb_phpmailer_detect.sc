if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809841" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-27 15:57:31 +0530 (Tue, 27 Dec 2016)" );
	script_name( "PHPMailer Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of PHPMailer Library.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
var version;
for dir in nasl_make_list_unique( "/PHPMailer-master", "/PHPMailer", "/phpmailer", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	mailer = FALSE;
	conclUrl = NULL;
	for path in make_list( "",
		 "/lib" ) {
		url = dir + path + "/composer.json";
		res = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"name\": \"phpmailer/phpmailer\"" ) && ContainsString( res, "class.phpmailer.php" )){
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			mailer = TRUE;
			for file in make_list( "/VERSION",
				 "/version" ) {
				url = dir + path + file;
				res = http_get_cache( item: url, port: port );
				if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
					vers = eregmatch( pattern: "\n([0-9.]+)", string: res );
					if(vers[1]){
						conclUrl += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
						version = vers[1];
						break;
					}
				}
			}
		}
		if( version ){
			break;
		}
		else {
			continue;
		}
	}
	if(!version){
		for file in make_list( "/README",
			 "/README.md" ) {
			url = dir + file;
			res = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "class.phpmailer.php" ) && ContainsString( res, "PHPMailer!" ) ) || ( ContainsString( res, "PHPMailer" ) && ( ContainsString( res, "A full-featured email creation and transfer class for PHP" ) || ContainsString( res, "Full Featured Email Transfer Class for PHP" ) ) )){
				conclUrl += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				mailer = TRUE;
				for file in make_list( "/changelog.txt",
					 "/ChangeLog.txt",
					 "/changelog.md" ) {
					url = dir + file;
					res = http_get_cache( item: url, port: port );
					if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "Change ?Log" ) && IsMatchRegexp( res, "\\* Ini?tial public release" )){
						vers = eregmatch( pattern: "Version ([0-9.]+)", string: res );
						if(vers[1]){
							conclUrl += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
							version = vers[1];
							break;
						}
					}
				}
			}
			if( version ){
				break;
			}
			else {
				continue;
			}
		}
	}
	if(!version){
		url = dir + "/extras";
		res = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "title>Index of.*extras" ) && ContainsString( res, "\"EasyPeasyICS.php" )){
			conclUrl += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			mailer = TRUE;
			url = dir + "/VERSION";
			res = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
				vers = eregmatch( pattern: "\n([0-9.]+)", string: res );
				if(vers[1]){
					conclUrl += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
					version = vers[1];
				}
			}
		}
	}
	if(mailer){
		if(!version){
			version = "unknown";
		}
		set_kb_item( name: "www/" + port + "/phpmailer", value: version );
		set_kb_item( name: "phpmailer/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:phpmailer_project:phpmailer:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:phpmailer_project:phpmailer";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PHPMailer", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ), port: port );
	}
}
exit( 0 );

