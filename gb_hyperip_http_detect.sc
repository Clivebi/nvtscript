if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108348" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NetEx HyperIP Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the remote host and attempts
  to detect the presence of NetEx HyperIP virtual appliance." );
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
buf = http_get_cache( item: "/", port: port );
if(ContainsString( buf, "<TITLE>HyperIP Home</TITLE>" )){
	version = "unknown";
	url = "/bstatus.php";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	vers = eregmatch( pattern: "hyperipCurVer\">([0-9.]+)</span>", string: buf );
	if(vers[1]){
		version = vers[1];
		set_kb_item( name: "hyperip/http/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "hyperip/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
	set_kb_item( name: "hyperip/http/" + port + "/version", value: version );
	set_kb_item( name: "hyperip/detected", value: TRUE );
	set_kb_item( name: "hyperip/http/detected", value: TRUE );
	set_kb_item( name: "hyperip/http/port", value: port );
}
exit( 0 );

