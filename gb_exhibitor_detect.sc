if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143180" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 06:25:49 +0000 (Tue, 26 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Exhibitor Detection" );
	script_tag( name: "summary", value: "Detection of Exhibitor.

  The script sends a connection request to the server and attempts to detect Exhibitor and extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443, 8181 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://github.com/soabase/exhibitor" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8181 );
url = "/exhibitor/v1/ui/index.html";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "\"app-name\">Exhibitor" ) && ContainsString( res, "Exhibitor for ZooKeeper" )){
	install = "/exhibitor";
	version = "unknown";
	url = "/exhibitor/v1/config/get-state";
	headers = make_array( "X-Requested-With", "XMLHttpRequest" );
	req = http_get_req( port: port, url: url, add_headers: headers );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	vers = eregmatch( pattern: "\"version\":\"v([0-9.]+)\"", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "exhibitor/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:exhibitor_project:exhibitor:" );
	if(!cpe){
		cpe = "cpe:/a:exhibitor_project:exhibitor";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Exhibitor", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

