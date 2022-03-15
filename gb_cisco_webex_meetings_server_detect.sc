if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106191" );
	script_version( "2020-11-25T14:53:04+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 14:53:04 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-08-19 11:08:48 +0700 (Fri, 19 Aug 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Webex Meetings Server Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Cisco Webex Meetings Server." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.cisco.com/c/en/us/products/conferencing/webex-meetings-server/index.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url1 = "/orion/login";
res1 = http_get_cache( port: port, item: url1 );
url2 = "/webappng/sites/meetings/dashboard/home";
res2 = http_get_cache( port: port, item: url2 );
if( IsMatchRegexp( res1, "<title>([^>]+Cisco WebEx|Cisco WebEx Meetings Server)</title>" ) && IsMatchRegexp( res1, "title=\"Cisco WebEx Meetings Server\"" ) ){
	found = TRUE;
	conclUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
}
else {
	if(ContainsString( res2, "<title>Cisco Webex Meetings</title>" ) && IsMatchRegexp( res2, "content=\"Cisco Webex (Meetings|Site)\"" )){
		found = TRUE;
		conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
	}
}
if(found){
	install = "/";
	version = "unknown";
	vers = eregmatch( pattern: "CWMS\\/([0-9_]+)\\/FAQs.html", string: res1 );
	if(!vers){
		vers = eregmatch( pattern: "CWMS\\/([0-9_]+)\\/Localizations/FAQs", string: res1 );
	}
	if(!isnull( vers[1] )){
		version = str_replace( string: vers[1], find: "_", replace: "." );
	}
	set_kb_item( name: "cisco/webex/meetings_server/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:webex_meetings_server:" );
	if(!cpe){
		cpe = "cpe:/a:cisco:webex_meetings_server";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Cisco Webex Meetings Server", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: conclUrl ), port: port );
}
exit( 0 );

