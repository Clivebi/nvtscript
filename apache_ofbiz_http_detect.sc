if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101019" );
	script_version( "2021-05-12T07:32:54+0000" );
	script_tag( name: "last_modification", value: "2021-05-12 07:32:54 +0000 (Wed, 12 May 2021)" );
	script_tag( name: "creation_date", value: "2009-04-18 23:46:40 +0200 (Sat, 18 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache OFBiz Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Apache Open For Business (OFBiz)." );
	script_xref( name: "URL", value: "https://ofbiz.apache.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8443 );
default_modules = make_list( "/accounting/control/main",
	 "/ap/control/main",
	 "/ar/control/main",
	 "/assetmaint/control/main",
	 "/bi/control/main",
	 "/birt/control/main",
	 "/catalog/control/main",
	 "/cmssite/control/main",
	 "/content/control/main",
	 "/control/main",
	 "/crmsfa/control/main",
	 "/ebay/control/main",
	 "/ebaystore/control/main",
	 "/ecommerce/control/main",
	 "/ecomseo",
	 "/example/control/main",
	 "/exampleext/control/main",
	 "/facility/control/main",
	 "/financials/control/main",
	 "/googlebase/control/main",
	 "/hhfacility/control/main",
	 "/humanres/control/main",
	 "/ldap/control/main",
	 "/lucence/control/main",
	 "/manufacturing/control/main",
	 "/marketing/control/main",
	 "/msggateway/control/main",
	 "/multiflex/control/main",
	 "/myportal/control/main",
	 "/ofbizsetup/control/main",
	 "/ordermgr/control/main",
	 "/passport/control/main",
	 "/partymgr/control/main",
	 "/pricat/control/main",
	 "/projectmgr/control/main",
	 "/purchasing/control/main",
	 "/scrum/control/main",
	 "/sfa/control/main",
	 "/sofami/control/main",
	 "/solr/control/main",
	 "/warehouse/control/main",
	 "/webpos/control/main",
	 "/webtools/control/main",
	 "/workeffort/control/main" );
for url in nasl_make_list_unique( "/", default_modules, http_cgi_dirs( port: port ) ) {
	module_base_path = url;
	if( url == "/control/main" ){
		module_base_path = "/";
	}
	else {
		if( ContainsString( url, "/control/main" ) ){
			module_base_path = str_replace( string: module_base_path, find: "/control/main", replace: "" );
		}
		else {
			if( ContainsString( url, "/ecomseo" ) || url == "/" ){
				}
			else {
				url += "/control/main";
			}
		}
	}
	res = http_get_cache( item: url, port: port );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	ofbizTitle = eregmatch( pattern: "<title>([a-zA-Z: &#0-9;\\-]+)</title>", string: res, icase: TRUE );
	if(( ofbizTitle && ContainsString( tolower( ofbizTitle[1] ), "ofbiz" ) ) || ContainsString( res, "neogia_logo.png" ) || ContainsString( res, "ofbiz_logo.png" ) || ContainsString( res, "ofbiz_logo.gif" ) || ContainsString( res, "/OfbizUtil.js" ) || ContainsString( res, "ofbiz.ico" ) || ContainsString( res, ">Apache OFBiz.<" ) || ContainsString( res, "OFBiz.Visitor" )){
		if( ofbizTitle && ContainsString( tolower( ofbizTitle[1] ), "ofbiz" ) ) {
			extra += "\n[" + ofbizTitle[1] + "]:" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			extra += "\n[Unknown module]:" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		installed = TRUE;
		set_kb_item( name: "apache/ofbiz/" + port + "/modules", value: module_base_path );
		if(!version){
			version = "unknown";
		}
		vers = eregmatch( pattern: "powered by <a href=\"http://ofbiz\\.apache\\.org\" target=\"_blank\">[a-zA-Z ]+ ([0-9.]+)", string: res, icase: TRUE );
		if( vers[1] && version == "unknown" ){
			version = vers[1];
		}
		else {
			vers = eregmatch( pattern: "powered by[ \r\n]*<a href=\"http://ofbiz\\.apache\\.org\" target=\"_blank\">.*release[\r\n]*([0-9.]+)", string: res, icase: TRUE );
			if(vers[1] && version == "unknown"){
				version = vers[1];
			}
		}
	}
}
if(installed){
	set_kb_item( name: "apache/ofbiz/detected", value: TRUE );
	install = "/";
	extra = "\n\nDetected Modules:\n" + extra;
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:ofbiz:" );
	if(!cpe){
		cpe = "cpe:/a:apache:ofbiz";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache OFBiz", version: version, install: install, cpe: cpe, concluded: vers[0] ) + extra, port: port );
}
exit( 0 );

