if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117504" );
	script_version( "2021-06-17T11:51:56+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 11:51:56 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 08:58:06 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WordPress Duplicator / Duplicator Pro Plugin Installer File Exposed (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://anonleaks.net/2021/optinfoil/kennotfm-details-zu-hack-und-defacement/" );
	script_xref( name: "URL", value: "https://www.synacktiv.com/ressources/advisories/WordPress_Duplicator-1.2.40-RCE.pdf" );
	script_tag( name: "summary", value: "One or more installer files of the WordPress plugins Duplicator /
  Duplicator Pro are exposed on the target system." );
	script_tag( name: "vuldetect", value: "Sends crafted HTTP GET requests and checks the responses." );
	script_tag( name: "impact", value: "Exposing these files poses the following risks:

  - Disclosure of sensitive data

  - Installation / overwriting of a WordPress installation on the target host

  - Some older versions of the installer are prone to a remote code execution (RCE) vulnerability" );
	script_tag( name: "affected", value: "All systems exposing installation files of the WordPress
  Duplicator / Duplicator Pro plugin." );
	script_tag( name: "solution", value: "Remove the installer files from the target system." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
tests = make_array( "/installer.php", "(<title>Duplicator[^>]+Installer</title>|DUPLICATOR[^>]*_INSTALLER_EOF\\s*-->|method=[\"\']post[\"\'] action=[\"\'][^>]+/main\\.installer\\.php[\"\'] />)", "/installer-backup.php", "(<title>Duplicator[^>]+Installer</title>|DUPLICATOR[^>]*_INSTALLER_EOF\\s*-->|method=[\"\']post[\"\'] action=[\"\'][^>]+/main\\.installer\\.php[\"\'] />)", "/database.sql", "/\\*\\s*DUPLICATOR[^/]+MYSQL[^/]+\\*/" );
report = "The following exposed files were identified:\n";
found = FALSE;
for dir in nasl_make_list_unique( "/", "/blog", "/wordpress", "/wp", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( tests ) {
		url = dir + file;
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		body = http_extract_body_from_response( data: res );
		if(!body){
			continue;
		}
		pattern = tests[file];
		if(egrep( pattern: pattern, string: body, icase: FALSE )){
			found = TRUE;
			report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			if(IsMatchRegexp( file, "/installer(-backup)?\\.php" )){
				archive = eregmatch( string: body, pattern: "name=[\"\']archive[\"\'] value=[\"\'][^>]+(/[^>]+_archive\\.zip)[\"\'] />", icase: FALSE );
				if(archive[1]){
					url = dir + archive[1];
					req = http_head( item: url, port: port );
					res = http_keepalive_send_recv( port: port, data: req );
					if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "Content-Type\\s*:\\s*application/zip" )){
						report += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
					}
				}
			}
		}
	}
}
if(found){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

