if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108531" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-20 14:05:39 +0100 (Sun, 20 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Adminer Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 12322 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.adminer.org/" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the remote
  server and tries to identify an Adminer installation and it's version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", "/adminer", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	if(rootInstalled){
		break;
	}
	url = dir + "/adminer.php";
	buf = http_get_cache( item: url, port: port );
	url2 = dir + "/";
	buf2 = http_get_cache( item: url2, port: port );
	if(( IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || IsMatchRegexp( buf2, "^HTTP/1\\.[01] 200" ) ) && ( ContainsString( buf, "<title>Login - Adminer</title>" ) || ContainsString( buf2, "<title>Login - Adminer</title>" ) || ( ContainsString( buf, "://www.adminer.org/'" ) && ContainsString( buf, "id='h1'>Adminer</a>" ) ) || ( ContainsString( buf2, "://www.adminer.org/'" ) && ContainsString( buf2, "id='h1'>Adminer</a>" ) ) )){
		version = "unknown";
		conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
		if(install == "/"){
			rootInstalled = TRUE;
		}
		vers = eregmatch( pattern: "verifyVersion(, '|\\(')([^']+)'", string: buf, icase: FALSE );
		if(vers[2]){
			version = vers[2];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "verifyVersion(, '|\\(')([^']+)'", string: buf2, icase: FALSE );
			if(vers[2]){
				version = vers[2];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "class=\"version\">([^<]+)<", string: buf, icase: FALSE );
			if(vers[1]){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "class=\"version\">([^<]+)<", string: buf2, icase: FALSE );
			if(vers[1]){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
		}
		set_kb_item( name: "www/" + port + "/adminer", value: version );
		set_kb_item( name: "adminer/detected", value: TRUE );
		register_and_report_cpe( app: "Adminer", ver: version, concluded: vers[0], conclUrl: conclUrl, base: "cpe:/a:adminer:adminer:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www" );
	}
}
exit( 0 );

