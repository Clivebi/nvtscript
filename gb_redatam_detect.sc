if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141196" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-19 13:09:25 +0700 (Tue, 19 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Redatam Detection" );
	script_tag( name: "summary", value: "Detection of Redatam.

  The script sends a connection request to the server and attempts to detect Redatam." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_keys( "Host/runs_windows" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://redatam.org/redatam/en/index.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/redbin/RpWebUtilities.exe";
res = http_get_cache( port: port, item: url );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( string: res, pattern: "<h1>(R\\+SP|Redatam) WebUtilities Default Action</h1>", icase: FALSE )){
	version = "unknown";
	conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
	set_kb_item( name: "redatam/installed", value: TRUE );
	cpe = "cpe:/a:redatam:redatam";
	register_product( cpe: cpe, location: "/redbin", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Redatam", version: version, install: "/redbin", cpe: cpe, concludedUrl: conclUrl ), port: port );
}
exit( 0 );

