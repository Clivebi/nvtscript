if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811915" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-10-05 17:44:54 +0530 (Thu, 05 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Trend Micro Smart Protection Server Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Trend Micro Smart Protection Server.

  This script performs a HTTP based detection of Trend Micro Smart Protection Server." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 4343 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://docs.trendmicro.com/en-us/enterprise/smart-protection-server.aspx" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 4343 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
res = http_get_cache( item: "/index.php", port: port );
if(ContainsString( res, "Trend Micro Smart Protection Server" ) && ContainsString( res, "Please type your user name and password to access the product console." )){
	version = "unknown";
	build = "unknown";
	set_kb_item( name: "trendmicro/sps/detected", value: TRUE );
	url = "/sysinfo";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	vers = eregmatch( pattern: "\"TMCSSVersion\": \"([0-9.]+)\"", string: res );
	if( !isnull( vers[1] ) ){
		version = vers[1];
		concluded = res;
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		bld = eregmatch( pattern: "\"TMCSSBuild\": \"([0-9]+)\"", string: res );
		if(!isnull( bld[1] )){
			build = bld[1];
		}
	}
	else {
		url = "/help/en_US.UTF-8/Introduction.html";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "\\.(css|js)\\?v=([0-9]+)", string: res );
		if(!isnull( vers[2] )){
			vers_build = vers[2];
			version = vers_build[0] + "." + vers_build[1];
			build = substr( vers_build, 2 );
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			concluded = vers[0];
		}
	}
	if(build != "unknown"){
		set_kb_item( name: "trendmicro/sps/build", value: build );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:trendmicro:smart_protection_server:" );
	if(!cpe){
		cpe = "cpe:/a:trendmicro:smart_protection_server";
	}
	os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Trend Micro Smart Protection Server Detection (HTTP)", runs_key: "unixoide" );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Trend Micro Smart Protection Server", version: version, patch: build, install: "/", cpe: cpe, concluded: concluded, concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

