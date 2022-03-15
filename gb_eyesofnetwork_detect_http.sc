if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108165" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-05-22 09:21:05 +0200 (Mon, 22 May 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Eyes Of Network (EON) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script attempts to identify the Eyes Of Network (EON)
  product via the HTTP login page and tries to extract the version number." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
buf = http_get_cache( item: "/login.php", port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>EyesOfNetwork</title>" ) || ContainsString( buf, "> Network and system Monitoring solution <" ) || ContainsString( buf, "<a href=\"http://www.eyesofnetwork.com\" target=\"_blank\">EyesOfNetwork</a>" ) || ContainsString( buf, "product under GPL2 license, sponsored by AXIANS" ) )){
	version = "unknown";
	url = "/css/menu.css";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	vers = eregmatch( pattern: "# VERSION ([0-9.]+)", string: buf );
	if( vers[1] ){
		version = vers[1];
	}
	else {
		url = "/README.md";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		vers = eregmatch( pattern: "EyesOfNetwork web interface ([0-9.]+)", string: buf );
		if(vers[1]){
			version = vers[1];
		}
	}
	if(version != "unknown"){
		set_kb_item( name: "eyesofnetwork/http/" + port + "/version", value: version );
		set_kb_item( name: "eyesofnetwork/http/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "eyesofnetwork/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
	url = "/eonapi/getApiKey";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	api_version = eregmatch( pattern: "\"api_version\": \"([0-9.]+)\"", string: buf );
	if(!isnull( api_version[1] )){
		set_kb_item( name: "eyesofnetwork/api/detected", value: TRUE );
		set_kb_item( name: "eyesofnetwork/api/version", value: api_version[1] );
	}
	set_kb_item( name: "eyesofnetwork/detected", value: TRUE );
	set_kb_item( name: "eyesofnetwork/http/detected", value: TRUE );
	set_kb_item( name: "eyesofnetwork/http/port", value: port );
}
exit( 0 );

