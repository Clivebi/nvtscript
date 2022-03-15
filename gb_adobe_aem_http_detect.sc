if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807067" );
	script_version( "2021-06-29T14:46:54+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-29 14:46:54 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-02-11 14:43:49 +0530 (Thu, 11 Feb 2016)" );
	script_name( "Adobe Experience Manager (AEM) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Adobe Experience Manager (AEM)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
detection_patterns = make_list( "<title>AEM Sign In",
	 ">Welcome to Adobe Experience Manager<",
	 "[0-9]+ Adobe.+All Rights Reserved",
	 "(src|href)=\"/etc/clientlibs/granite/",
	 "(src|href)=\"/content/dam/",
	 "(src|href)=\"/etc/designs/",
	 "(src|href)=\"/etc\\.clientlibs/clientlibs/granite/",
	 "^[Xx]-[Aa]dobe-[Cc]ontent\\s*:\\s*AEM" );
host = http_host_name( dont_add_port: TRUE );
for url in make_list( "/libs/granite/core/content/login.html?",
	 "/" ) {
	found = 0;
	concluded = "";
	res = http_get_cache( item: url, port: port );
	if(( res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) ) || IsMatchRegexp( banner, "X-Adobe-Content" )){
		for pattern in detection_patterns {
			if( ContainsString( pattern, "[Xx]-[Aa]dobe-[Cc]ontent" ) ) {
				concl = egrep( string: banner, pattern: pattern, icase: TRUE );
			}
			else {
				concl = egrep( string: res, pattern: pattern, icase: FALSE );
			}
			if(concl){
				concl = split( buffer: concl, keep: FALSE );
				concl = concl[0];
				if(concluded){
					concluded += "\n";
				}
				concl = chomp( concl );
				concl = ereg_replace( string: concl, pattern: "^(\\s+)", replace: "" );
				concluded += "    " + concl;
				if( ContainsString( pattern, "[Xx]-[Aa]dobe-[Cc]ontent" ) ) {
					found += 2;
				}
				else {
					found++;
				}
			}
		}
		if(found > 1){
			version = "unknown";
			install = "/";
			set_kb_item( name: "adobe/aem/detected", value: TRUE );
			set_kb_item( name: "adobe/aem/http/detected", value: TRUE );
			concludedUrl = "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			for url in make_list( "/system/console",
				 "/system/console/configMgr",
				 "/system/console/bundles" ) {
				res = http_get_cache( item: url, port: port );
				if(IsMatchRegexp( res, "^HTTP/1\\.[01] 401" ) && ContainsString( res, "OSGi Management Console" )){
					set_kb_item( name: "www/content/auth_required", value: TRUE );
					set_kb_item( name: "www/" + host + "/" + port + "/content/auth_required", value: url );
					extra = "The OSGi Management Console is reachable at: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
					break;
				}
			}
			url = "/system/sling/cqform/defaultlogin.html";
			res = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "QUICKSTART_HOMEPAGE" )){
				extra += "\nThe Sling console is reachable at: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			url = "/crx/de/index.jsp";
			res = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<title>CRXDE Lite</title>" ) || ContainsString( res, "icons/crxde_favicon.ico" ) )){
				extra += "\nThe CRXDE console is reachable at: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			cpe = "cpe:/a:adobe:experience_manager";
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Adobe Experience Manager", version: version, install: install, cpe: cpe, concluded: concluded, concludedUrl: concludedUrl, extra: extra ), port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

