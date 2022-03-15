if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112335" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-25 11:05:12 +0200 (Wed, 25 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Northern Electric & Power (NEP) Inverter Monitor Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script sends an HTTP GET request to figure out whether an NEP Inverter monitor is running on the target host and which version is installed." );
	script_xref( name: "URL", value: "http://www.northernep.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
CPE = "cpe:/h:northernep:inverter_monitor:";
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/nep/status/index", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	resp = http_get_cache( item: url, port: port );
	if(eregmatch( pattern: "<title>(Null|NEP) Inverter Monitor</title>", string: resp, icase: TRUE ) && ( ContainsString( resp, "Energy Output</a>" ) || ContainsString( resp, "Auto-refresh Inverter Status</label>" ) )){
		set_kb_item( name: "northernep/inverter_monitor/detected", value: TRUE );
		version = "unknown";
		version_match = eregmatch( pattern: "Version:([0-9.]+)", string: resp );
		if(version_match[1]){
			version = version_match[1];
			concluded_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		register_and_report_cpe( app: "NEP Inverter Monitor", ver: version, concluded: version_match[0], base: CPE, expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: concluded_url );
		exit( 0 );
	}
}

