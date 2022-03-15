if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105521" );
	script_version( "2021-02-20T13:08:51+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-20 13:08:51 +0000 (Sat, 20 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-01-19 17:03:19 +0100 (Tue, 19 Jan 2016)" );
	script_name( "Cisco Firepower Management Center (FMC) Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Cisco Firepower Management Center (FMC)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url1 = "/login.cgi";
res1 = http_get_cache( port: port, item: url1 );
if(!ContainsString( res1, "<title>Login</title>" ) || !ContainsString( res1, "Cisco" ) || ( !ContainsString( res1, "askToClearSession" ) && !ContainsString( res1, "SF.Modal" ) )){
	exit( 0 );
}
version = "unknown";
build = "unknown";
model = "unknown";
url2 = "/ui/login";
res2 = http_get_cache( port: port, item: url2 );
vers = eregmatch( pattern: "'version': '([0-9.]+)',", string: res2 );
if( !isnull( vers[1] ) ){
	version = vers[1];
	bld = eregmatch( pattern: "'build': '([0-9]+)',", string: res2 );
	if(!isnull( bld[1] )){
		build = bld[1];
	}
	mod = eregmatch( pattern: "'model': 'Cisco Firepower Management Center ([^']+)',", string: res2 );
	if(!isnull( mod[1] )){
		if( ContainsString( mod[1], "for " ) ) {
			model = "VM";
		}
		else {
			model = mod[1];
		}
	}
	concUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
}
else {
	vers = eregmatch( pattern: "\\?v=([0-9.]+)-([0-9]+)", string: res1 );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	if(!isnull( vers[2] )){
		build = vers[2];
	}
	concUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
}
set_kb_item( name: "cisco/firepower_management_center/detected", value: TRUE );
set_kb_item( name: "cisco/firepower_management_center/http/port", value: port );
set_kb_item( name: "cisco/firepower_management_center/http/" + port + "/model", value: model );
set_kb_item( name: "cisco/firepower_management_center/http/" + port + "/version", value: version );
set_kb_item( name: "cisco/firepower_management_center/http/" + port + "/build", value: build );
set_kb_item( name: "cisco/firepower_management_center/http/" + port + "/concludedUrl", value: concUrl );
exit( 0 );

