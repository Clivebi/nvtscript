if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113619" );
	script_version( "2020-11-20T06:21:12+0000" );
	script_tag( name: "last_modification", value: "2020-11-20 06:21:12 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-12-17 16:17:18 +0200 (Tue, 17 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Oracle Application / HTTP Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Oracle-Application-or-HTTP-Server/banner" );
	script_tag( name: "summary", value: "Checks whether the Oracle Application Server
  or the Oracle HTTP Server is present on the target system and if so,
  tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.oracle.com/middleware/technologies/internet-application-server.html" );
	script_xref( name: "URL", value: "https://docs.oracle.com/cd/E28280_01/web.1111/e10144/intro_ohs.htm#HSADM102" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_remote_headers( port: port );
if(IsMatchRegexp( buf, "Server: *Oracle[ -]Application[ -]Server" )){
	set_kb_item( name: "oracle/application_server/detected", value: TRUE );
	set_kb_item( name: "oracle/tnslsnr_or_application_server/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "[0-9]{1,2}[a-zA-Z]?(/| \\()([0-9.]+)" );
	if(!isnull( ver[2] )){
		version = ver[2];
	}
	register_and_report_cpe( app: "Oracle Application Server", ver: version, concluded: ver[0], base: "cpe:/a:oracle:application_server:", expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
if(IsMatchRegexp( buf, "Server:[^\n]*Oracle[ -]HTTP[ -]Server" )){
	set_kb_item( name: "oracle/http_server/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "[0-9]{1,2}g(/| \\()([0-9.]+)" );
	if(!isnull( ver[2] )){
		version = ver[2];
	}
	register_and_report_cpe( app: "Oracle HTTP Server", ver: version, concluded: ver[0], base: "cpe:/a:oracle:http_server:", expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

