if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140134" );
	script_version( "2021-10-04T09:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 09:24:26 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2017-01-31 12:34:46 +0100 (Tue, 31 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell EMC Isilon InsightIQ Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Dell EMC Isilon InsightIQ." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.dell.com/support/kbdoc/en-us/000129563/insightiq-isilon-info-hub" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/login";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<title>Isilon InsightIQ</title>" ) && ContainsString( res, "Welcome to InsightIQ. Please log in" )){
	version = "unknown";
	vers = eregmatch( pattern: "\"version\">v?([0-9.]+)<", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "emc/isilon_insightiq/detected", value: TRUE );
	set_kb_item( name: "emc/isilon_insightiq/http/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:emc:isilon_insightiq:" );
	if(!cpe){
		cpe = "cpe:/a:emc:isilon_insightiq";
	}
	os_register_and_report( os: "Linux", version: "cpe:/o:linux:kernel", runs_key: "linux", desc: "Dell EMC Isilon InsightIQ Detection (HTTP)" );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dell EMC Isilon InsightIQ", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

