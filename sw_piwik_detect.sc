if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111046" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-05 13:00:00 +0100 (Thu, 05 Nov 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Piwik Analytics Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://piwik.org/" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the server
  and attempts to identify Piwik and its version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/piwik", "/analytics", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( eregmatch( pattern: "<title>.*Piwik.*</title>", string: buf, icase: TRUE ) || ( ContainsString( buf, "piwik.piwik_url" ) && ( ContainsString( buf, "http://piwik.org" ) || ContainsString( buf, "https://piwik.org" ) ) ) )){
		version = "unknown";
		url = dir + "/CHANGELOG.md";
		buf = http_get_cache( item: url, port: port );
		ver = eregmatch( pattern: "## Piwik ([0-9.]+)", string: buf );
		if(!isnull( ver[1] )){
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			extra = "Possible version gathered from the developers CHANGELOG.md: " + ver[1] + "\n";
			extra += "NOTE: This version is not necessarily matching the running version and currently not used.";
		}
		cpe = "cpe:/a:piwik:piwik";
		set_kb_item( name: "www/" + port + "/piwik", value: version );
		set_kb_item( name: "piwik/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Piwik", version: version, install: install, cpe: cpe, extra: extra, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

