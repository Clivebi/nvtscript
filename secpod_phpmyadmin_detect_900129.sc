if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900129" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-10-03 15:12:54 +0200 (Fri, 03 Oct 2008)" );
	script_name( "phpMyAdmin Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of phpMyAdmin.

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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
check_dirs = make_list( "/pHpmyADmiN",
	 "/PhPmyAdMin",
	 "/phPmYaDmiN",
	 "/phpMyadMiN" );
alias = TRUE;
ac = 0;
for cd in check_dirs {
	res = http_get_cache( item: cd + "/index.php", port: port );
	if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		alias = FALSE;
		ac = 0;
		break;
	}
	ac++;
}
if(ac != 4){
	alias = FALSE;
}
for dir in nasl_make_list_unique( "/", "/phpmyadmin", "/phpMyAdmin", "/pma", "/PHPMyAdmin", "/3rdparty/phpMyAdmin", "/3rdparty/phpmyadmin", "/.tools/phpMyAdmin/current", http_cgi_dirs( port: port ) ) {
	if(ContainsString( dir, "/setup" )){
		continue;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(egrep( pattern: "^Set-Cookie: pma_.*", string: res ) || egrep( pattern: "^Set-Cookie: phpMyAdmin.*", string: res ) || egrep( pattern: "phpMyAdmin was unable to read your configuration file", string: res ) || egrep( pattern: "<title>phpMyAdmin.*", string: res ) || egrep( pattern: "href=.*phpmyadmin.css.php" ) || ( egrep( pattern: "pma_password", string: res ) && egrep( pattern: "pma_username", string: res ) )){
		version = "unknown";
		vers = eregmatch( pattern: "phpMyAdmin (([0-9.]+)(-[betadevrc0-9]*)?)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			url = dir + "/README";
			res1 = http_get_cache( item: url, port: port );
			vers = eregmatch( pattern: "Version (([0-9.]+)(-[betadevrc0-9]*)?)", string: res1 );
			if(!isnull( vers[1] )){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			url = dir + "/doc/html/index.html";
			res1 = http_get_cache( item: url, port: port );
			vers = eregmatch( pattern: "phpMyAdmin (([0-9.]+)(-[betadevrc0-9]*)?) documentation", string: res1 );
			if(!isnull( vers[1] )){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			url = dir + "/docs/html/index.html";
			res1 = http_get_cache( item: url, port: port );
			vers = eregmatch( pattern: "phpMyAdmin (([0-9.]+)(-[betadevrc0-9]*)?) documentation", string: res1 );
			if(!isnull( vers[1] )){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			url = dir + "/ChangeLog";
			req = http_get( item: url, port: port );
			res1 = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(ContainsString( res1, "phpMyAdmin - ChangeLog" )){
				vers = eregmatch( pattern: "(([0-9.]+)(-[betadevrc0-9]*)?) \\(", string: res1 );
				if(!isnull( vers[1] )){
					version = vers[1];
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
		if(version == "unknown"){
			url = dir + "/Documentation.html";
			res1 = http_get_cache( item: url, port: port );
			vers = eregmatch( pattern: "phpMyAdmin (([0-9.]+)( -[betadevrc0-9]*)?) Documentation", string: res1 );
			if(!isnull( vers[1] )){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			url = dir + "/changelog.php";
			req = http_get( item: url, port: port );
			res1 = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(ContainsString( res1, "phpMyAdmin - ChangeLog" )){
				vers = eregmatch( pattern: "(([0-9.]+)(-[betadevrc0-9]*)?) \\(", string: res1 );
				if(!isnull( vers[1] )){
					version = vers[1];
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
		protected = 0;
		if(egrep( pattern: "1045", string: res ) || egrep( pattern: "phpMyAdmin was unable to read your configuration file", string: res )){
			protected = 2;
		}
		if(egrep( pattern: "pma_username", string: res ) && egrep( pattern: "pma_password", string: res )){
			protected = 1;
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/phpMyAdmin", value: tmp_version );
		set_kb_item( name: "phpMyAdmin/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+.*(-[betadevrc0-9]*)?)", base: "cpe:/a:phpmyadmin:phpmyadmin:" );
		if(!cpe){
			cpe = "cpe:/a:phpmyadmin:phpmyadmin";
		}
		if( protected == 0 ){
			info = "- Not protected by Username/Password";
		}
		else {
			if( protected == 2 ){
				info = "- Problem with configuration file";
			}
			else {
				info = "- Protected by Username/Password";
			}
		}
		url = dir + "/setup/";
		res1 = http_get_cache( item: url, port: port );
		if(ContainsString( res1, "<title>phpMyAdmin setup</title>" )){
			info = "\n- Possible unprotected setup dir identified at " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "phpMyAdmin", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: conclUrl, extra: info ), port: port );
		if(alias){
			break;
		}
	}
}
exit( 0 );

