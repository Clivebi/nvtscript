if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107342" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-11 16:21:34 +0200 (Thu, 11 Oct 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OctoPrint Version Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of OctoPrint Web UI for 3D printers using HTTP." );
	script_xref( name: "URL", value: "https://octoprint.org/download/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner = egrep( string: banner, pattern: "Basic realm.+OctoPrint", icase: TRUE )){
	found = TRUE;
	auth = TRUE;
	concluded = chomp( banner );
}
if(!found){
	buf = http_get_cache( item: "/", port: port );
	if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "OctoPrint</title>" ) && ContainsString( buf, "octoprint.org" ) ) || ContainsString( buf, "<title>OctoPrint Login</title>" )){
		found = TRUE;
		auth = FALSE;
	}
}
if(found){
	install = "/";
	version = "unknown";
	conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	set_kb_item( name: "octoprint/detected", value: TRUE );
	set_kb_item( name: "octoprint/http/port", value: port );
	if( auth ) {
		set_kb_item( name: "octoprint/detected/auth", value: TRUE );
	}
	else {
		set_kb_item( name: "octoprint/detected/noauth", value: TRUE );
	}
	vers = eregmatch( pattern: "var DISPLAY_VERSION = \"([0-9.]+)\"", string: buf, icase: TRUE );
	if(vers[1]){
		version = vers[1];
		concluded = vers[0];
	}
	set_kb_item( name: "octoprint/http/version", value: version );
	set_kb_item( name: "octoprint/http/concluded", value: concluded );
	register_and_report_cpe( app: "OctoPrint Web UI", ver: version, concluded: concluded, base: "cpe:/a:octoprint:octoprint:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www", conclUrl: conclUrl );
}
exit( 0 );

