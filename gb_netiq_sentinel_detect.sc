if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105618" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-21 16:30:22 +0200 (Thu, 21 Apr 2016)" );
	script_name( "NetIQ Sentinel Detection" );
	script_tag( name: "summary", value: "Detection of NetIQ Sentinel

The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8443 );
url = "/sentinel/views/logon.html";
buf = http_get_cache( item: url, port: port );
if(!IsMatchRegexp( buf, "HTTP/1\\.. 200" ) || !ContainsString( buf, "<title>NetIQ Sentinel Login" )){
	exit( 0 );
}
vers = "unknown";
cpe = "cpe:/a:netiq:sentinel";
set_kb_item( name: "netiq_sentinel/installed", value: TRUE );
url = "/baselining/version";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "version" )){
	version = eregmatch( pattern: "\"version\":\"([0-9]+[^\"]+)\"", string: buf );
	if(!isnull( version[1] )){
		vers = version[1];
		cpe += ":" + vers;
		set_kb_item( name: "netiq_sentinel/version", value: vers );
		concUrl = url;
	}
}
if(ContainsString( buf, "\"rev\":\"" )){
	_r = eregmatch( pattern: "\"rev\":\"([0-9]+[^\"]+)\"", string: buf );
	if(!isnull( _r[1] )){
		set_kb_item( name: "netiq_sentinel/rev", value: _r[1] );
		revision = _r[1];
	}
}
register_product( cpe: cpe, location: "/sentinel", port: port, service: "www" );
log_message( data: build_detection_report( app: "NetIQ Sentinel", version: vers, install: "/sentinel", cpe: cpe, concluded: version[0], concludedUrl: concUrl, extra: "Revision: " + revision ), port: port );
exit( 0 );

