if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113572" );
	script_version( "2020-08-24T15:44:25+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:44:25 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-22 13:03:22 +0200 (Fri, 22 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Zeus Web Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Zeus/banner" );
	script_tag( name: "summary", value: "Checks whether Zeus Web Server is present
  on the target system and if so, tried to figure out the installed version." );
	exit( 0 );
}
CPE = "cpe:/a:zeus:zeus_web_server:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_remote_headers( port: port );
if(IsMatchRegexp( buf, "Server: *Zeus" )){
	set_kb_item( name: "zeus_web_server/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "Zeus/([0-9._]+)" );
	if(!isnull( ver[1] )){
		version = str_replace( string: ver[1], find: "_", replace: "." );
	}
	register_and_report_cpe( app: "Zeus Web Server", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

