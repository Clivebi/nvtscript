if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113663" );
	script_version( "2020-08-24T15:44:25+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:44:25 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-03-31 13:21:43 +0100 (Tue, 31 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cassini / CassiniEx Web Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "cassini/banner" );
	script_tag( name: "summary", value: "Checks whether Cassini / CassiniEx Web Server is present on
  the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/de-de/previous-versions/technical-content/bb979483(v=msdn.10)" );
	script_xref( name: "URL", value: "https://soderlind.no/cassiniex-web-server/" );
	exit( 0 );
}
CPE = "cpe:/a:microsoft:cassini";
APP = "Cassini";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(IsMatchRegexp( banner, "Server\\s*:\\s*(Microsoft-)?Cassini" )){
	set_kb_item( name: "microsoft/cassini/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: banner, pattern: "Server\\s*:\\s*(Microsoft-)?Cassini(Ex)?/([0-9.]+)", icase: TRUE );
	if(!isnull( ver[3] )){
		version = ver[3];
	}
	if(ver[2]){
		CPE += "ex";
		APP += "Ex";
	}
	register_and_report_cpe( app: APP + " Web Server", ver: version, concluded: ver[0], base: CPE + ":", expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

