if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105227" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-02-09 12:00:00 +0100 (Mon, 09 Feb 2015)" );
	script_name( "Magento Shop Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of the installation path and version
  of a Magento Shop.

  The script sends HTTP GET requests and tries to confirm the Magento Shop installation
  path and version from the responses." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", "/magento", "/shop", http_cgi_dirs( port: port ) ) {
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	flag = FALSE;
	outdatedChangelog = FALSE;
	CE = FALSE;
	EE = FALSE;
	url1 = dir + "/admin/";
	res1 = http_get_cache( item: url1, port: port );
	url2 = dir + "/";
	res2 = http_get_cache( item: url2, port: port );
	url3 = dir + "/RELEASE_NOTES.txt";
	res3 = http_get_cache( item: url3, port: port );
	url4 = dir + "/downloader/";
	res4 = http_get_cache( item: url4, port: port );
	if(res1 && ContainsString( res1, "Magento Inc." ) || res2 && ( ContainsString( res2, "/skin/frontend/" ) || ContainsString( res2, "text/x-magento-init" ) ) || res3 && ContainsString( res3, "=== Improvements ===" ) || res4 && ContainsString( res4, "Magento Connect Manager ver." )){
		version = "unknown";
		if(dir == ""){
			rootInstalled = TRUE;
		}
		ver = eregmatch( pattern: "==== ([0-9\\.]+) ====", string: res3 );
		if(ver[1] && ( version_is_less_equal( version: ver[1], test_version: "1.7.0.2" ) && !ContainsString( res3, "NOTE: Current Release Notes are maintained at:" ) ) || version_is_greater_equal( version: ver[1], test_version: "1.9.1.0" )){
			conclUrl = http_report_vuln_url( port: port, url: url3, url_only: TRUE );
			version = ver[1];
			flag = TRUE;
			if(ContainsString( res3, "NOTE: Current Release Notes are maintained at:" )){
				outdatedChangelog = TRUE;
			}
		}
		if(!flag){
			ver = eregmatch( pattern: "Magento Connect Manager ver. ([0-9\\.]+)", string: res4 );
			if(ver[1] && version_is_less_equal( version: ver[1], test_version: "1.7.0.2" ) && !outdatedChangelog){
				conclUrl = http_report_vuln_url( port: port, url: url4, url_only: TRUE );
				version = ver[1];
			}
		}
		if(res3 && ContainsString( res3, "magento" ) && ContainsString( res3, "=== Improvements ===" )){
			if( IsMatchRegexp( res3, "(c|C)ommunity_(e|E)dition" ) ){
				CE = TRUE;
				extra = "\nEdition gathered from:\n" + http_report_vuln_url( port: port, url: url3, url_only: TRUE );
			}
			else {
				if(IsMatchRegexp( res3, "(e|E)nterprise (E|e)dition" )){
					EE = TRUE;
					extra = "\nEdition gathered from:\n" + http_report_vuln_url( port: port, url: url3, url_only: TRUE );
				}
			}
		}
		url7 = dir + "/magento_version";
		req = http_get( item: url7, port: port );
		res7 = http_keepalive_send_recv( port: port, data: req );
		ver = eregmatch( pattern: "Magento/([0-9.]+) \\((Community|Enterprise)\\)", string: res7 );
		if(!isnull( ver[1] )){
			version = ver[1];
			conclUrl = http_report_vuln_url( port: port, url: url7, url_only: TRUE );
			if(!isnull( ver[2] )){
				if( ver[2] == "Enterprise" ) {
					EE = TRUE;
				}
				else {
					CE = TRUE;
				}
			}
		}
		if(!EE || !CE){
			url5 = dir + "/errors/enterprise/css/styles.css";
			req = http_get( item: url5, port: port );
			res5 = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if( res5 && IsMatchRegexp( res5, "(M|m)agento (E|e)nterprise (E|e)dition" ) && IsMatchRegexp( res5, "license.*enterprise.edition" ) ){
				EE = TRUE;
				extra = "\nEdition gathered from:\n" + http_report_vuln_url( port: port, url: url5, url_only: TRUE );
			}
			else {
				url6 = dir + "/errors/default/css/styles.css";
				req = http_get( item: url6, port: port );
				res6 = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(res6 && IsMatchRegexp( res6, "(M|m)agento" ) && IsMatchRegexp( res6, "license.*opensource.*Free" )){
					CE = TRUE;
					extra = "\nEdition gathered from:\n" + http_report_vuln_url( port: port, url: url6, url_only: TRUE );
				}
			}
		}
		if( CE ){
			set_kb_item( name: "magento/CE/installed", value: TRUE );
			app = "Magento Community Edition";
		}
		else {
			if( EE ){
				set_kb_item( name: "magento/EE/installed", value: TRUE );
				app = "Magento Enterprise Edition";
			}
			else {
				app = "Magento Unknown Edition";
			}
		}
		set_kb_item( name: "magento/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "([0-9a-z.]+)", base: "cpe:/a:magentocommerce:magento:" );
		if(isnull( cpe ) || version == "unknown"){
			cpe = "cpe:/a:magentocommerce:magento";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: app, version: version, install: install, cpe: cpe, extra: extra, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

