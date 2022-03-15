if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101021" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-23 00:18:39 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Opentaps ERP + CRM Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host is running Opentaps ERP + CRM.

  Opentaps is a full-featured ERP + CRM suite which incorporates several open source projects, including:

  - Apache Geronimo, Tomcat, and OFBiz for the data model and transaction framework

  - Pentaho and JasperReports for business intelligence

  - Funambol for mobile device and Outlook integration

  - The Opentaps applications which provide user-driven applications for CRM, accounting and finance,
  warehouse and manufacturing, and purchasing and supply chain management." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for module in make_list( "/activities",
	 "/amazon",
	 "/asterisk",
	 "/catalog",
	 "/crmsfa",
	 "/controllerinjectex",
	 "/dataimport",
	 "/ebay",
	 "/ecommerce",
	 "/financials",
	 "/googlebase",
	 "/opentaps",
	 "/partymgr",
	 "/purchasing",
	 "/search",
	 "/warehouse",
	 "/webstore",
	 "/webtools" ) {
	url = module + "/control/main";
	res = http_get_cache( item: url, port: port );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	opentapsTitle = eregmatch( pattern: "<title>([a-zA-Z: &#0-9;\\.\\-]+)</title>", string: res, icase: TRUE );
	if(( opentapsTitle && ContainsString( tolower( opentapsTitle[1] ), "opentaps" ) ) || ContainsString( res, "opentaps_logo.png" )){
		if( opentapsTitle && ContainsString( tolower( opentapsTitle[1] ), "opentaps" ) ) {
			extra_otaps += "\n[" + opentapsTitle[1] + "]:" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			if( opentapsTitle && ContainsString( tolower( opentapsTitle[1] ), "ofbiz" ) ) {
				extra_ofbiz += "\n[" + opentapsTitle[1] + "]:" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			else {
				extra_otaps += "\n[Unknown module]:" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		installed = TRUE;
		set_kb_item( name: "OpentapsERP/" + port + "/modules", value: module );
		if(!version){
			version = "unknown";
		}
		if(version == "unknown"){
			vers = eregmatch( pattern: "<a href=\"http://www.opentaps.org\"( class=\"tabletext\")?>opentaps[^<]+</a> ([0-9.]+).<br ?/>", string: res, icase: TRUE );
			if(vers[2]){
				version = vers[2];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
}
if(installed){
	set_kb_item( name: "OpentapsERP/installed", value: TRUE );
	set_kb_item( name: "OpentapsERP/" + port + "/version", value: version );
	install = "/";
	if(extra_otaps){
		extra += "\n\nDetected Opentaps Modules:\n" + extra_otaps;
	}
	if(extra_ofbiz){
		extra += "\n\nDetected OFBiz Modules on Opentaps:\n" + extra_ofbiz;
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:opentaps:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:apache:opentaps";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Opentaps ERP + CRM", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ) + extra, port: port );
}
exit( 0 );

