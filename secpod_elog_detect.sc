if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901008" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ELOG Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "ELOG_HTTP/banner" );
	script_require_ports( "Services/www", 8080, 443 );
	script_tag( name: "summary", value: "Detection of ELOG.

  The script sends a connection request to the server and attempts to detect ELOG and to extract its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://elog.psi.ch/elog/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!IsMatchRegexp( banner, "[Ss]erver: ?ELOG[ -]" )){
	exit( 0 );
}
install = "/";
version = "unknown";
vers = eregmatch( pattern: "Server: ELOG HTTP (([0-9.]+)-?([0-9a-f]+)?)", string: banner, icase: TRUE );
if(!isnull( vers[1] )){
	version = ereg_replace( pattern: "-$", string: vers[1], replace: "" );
	version = ereg_replace( pattern: "-", string: version, replace: "." );
}
set_kb_item( name: "ELOG/detected", value: TRUE );
register_and_report_cpe( app: "ELOG", ver: version, concluded: vers[0], base: "cpe:/a:stefan_ritt:elog_web_logbook:", expr: "^([0-9a-f.]+)", insloc: install, regPort: port, regService: "www" );
exit( 0 );

