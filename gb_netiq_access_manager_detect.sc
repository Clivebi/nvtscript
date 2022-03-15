if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105148" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-31T08:09:36+0000" );
	script_tag( name: "last_modification", value: "2021-03-31 08:09:36 +0000 (Wed, 31 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-12-19 14:59:27 +0100 (Fri, 19 Dec 2014)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Micro Focus / NetIQ Access Manager Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Micro Focus / NetIQ Access Manager." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.microfocus.com/en-us/cyberres/identity-access-management/access-manager" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/nidp/app";
buf = http_get_cache( item: url, port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 30[0-9]" )){
	loc = http_extract_location_from_redirect( port: port, data: buf, current_dir: "/" );
	if(loc){
		url = loc;
		buf = http_get_cache( item: url, port: port );
	}
}
if(!buf || ( !IsMatchRegexp( buf, "<title>(NetIQ )?Access Manager" ) && !ContainsString( buf, "/nidp/app/login?id=" ) && !ContainsString( buf, "UrnNovellNidpClusterMemberId" ) )){
	exit( 0 );
}
set_kb_item( name: "netiq_access_manager/installed", value: TRUE );
version = "unknown";
version_url = "/nidp/html/help/en/bookinfo.html";
version_resp = http_get_cache( item: version_url, port: port );
version_match = eregmatch( pattern: "Access Manager ([0-9.]+) User Portal Help", string: version_resp );
if(version_match[1]){
	version = version_match[1];
	concluded_url = http_report_vuln_url( port: port, url: version_url, url_only: TRUE );
}
cpe1 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:microfocus:access_manager:" );
cpe2 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:netiq:access_manager:" );
if(!cpe1){
	cpe1 = "cpe:/a:microfocus:access_manager";
	cpe2 = "cpe:/a:netiq:access_manager";
}
register_product( cpe: cpe1, location: "/", port: port, service: "www" );
register_product( cpe: cpe2, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Micro Focus / NetIQ Access Manager", version: version, cpe: cpe1, install: "/", concluded: version_match[0], concludedUrl: concluded_url ), port: port );
exit( 0 );

