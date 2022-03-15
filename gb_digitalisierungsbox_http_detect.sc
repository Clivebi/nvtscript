if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143195" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-28 04:26:14 +0000 (Thu, 28 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Digitalisierungsbox Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Digitalisierungsbox.

  The script sends a connection request to the server and attempts to detect Digitalisierungsbox." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8443, 4443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/cgi-bin/status.xml";
res = http_get_cache( port: port, item: url );
if(!ContainsString( res, "Digitalisierungsbox" ) || !ContainsString( res, "<sysName>" )){
	url = "/";
	res = http_get_cache( port: port, item: url );
	if(!ContainsString( res, "title=\"Digitalisierungsbox" ) || !ContainsString( res, "Env.setAppName" )){
		exit( 0 );
	}
}
version = "unknown";
model = "unknown";
set_kb_item( name: "digitalisierungsbox/detected", value: TRUE );
set_kb_item( name: "digitalisierungsbox/http/port", value: port );
mod = eregmatch( pattern: "Digitalisierungsbox (STANDARD|BASIC|SMART|PREMIUM)", string: res, icase: TRUE );
if(!isnull( mod[1] )){
	model = mod[1];
}
vers = eregmatch( pattern: "<firmware>([0-9.]+)", string: res );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "digitalisierungsbox/http/" + port + "/concluded", value: vers[0] );
	set_kb_item( name: "digitalisierungsbox/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
}
set_kb_item( name: "digitalisierungsbox/http/" + port + "/model", value: model );
set_kb_item( name: "digitalisierungsbox/http/" + port + "/version", value: version );
exit( 0 );

