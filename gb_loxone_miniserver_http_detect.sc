if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107044" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-01-21T10:52:02+0000" );
	script_tag( name: "last_modification", value: "2021-01-21 10:52:02 +0000 (Thu, 21 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-09-07 13:18:59 +0200 (Wed, 07 Sep 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Loxone Miniserver Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Loxone Miniserver devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
res = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( banner, "Server\\s*:\\s*Loxone" ) || ( ( ContainsString( res, "title>Loxone</title>" ) || ContainsString( res, "CloudDNS" ) ) && ( IsMatchRegexp( res, "frame-src 'self' [^.]+\\.loxone\\.com" ) || ContainsString( res, "loxoneControl.js" ) || ContainsString( res, "loxCSSCommon.css" ) ) )){
	version = "unknown";
	set_kb_item( name: "loxone/miniserver/detected", value: TRUE );
	set_kb_item( name: "loxone/miniserver/http/detected", value: TRUE );
	set_kb_item( name: "loxone/miniserver/http/port", value: port );
	url = "/jdev/cfg/apiKey";
	headers = make_array( "X-Requested-With", "XMLHttpRequest" );
	req = http_get_req( port: port, url: url, add_headers: headers );
	res2 = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "'version':'([0-9.]+)'", string: res2 );
	if( !isnull( vers[1] ) ){
		version = vers[1];
		set_kb_item( name: "loxone/miniserver/http/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "loxone/miniserver/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
	else {
		vers = eregmatch( pattern: "Server\\s*:\\s*Loxone ([0-9.]+)", string: res, icase: TRUE );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "loxone/miniserver/http/" + port + "/concluded", value: vers[0] );
		}
	}
	set_kb_item( name: "loxone/miniserver/http/" + port + "/version", value: version );
}
exit( 0 );

