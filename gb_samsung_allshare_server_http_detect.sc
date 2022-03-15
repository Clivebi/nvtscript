if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113664" );
	script_version( "2020-08-24T15:44:25+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:44:25 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-03 09:47:59 +0100 (Fri, 03 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Samsung AllShare Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "allshare/banner" );
	script_tag( name: "summary", value: "Checks whether Samsung AllShare Server is present on
  the target system and if so, tries to figure out the installed version." );
	exit( 0 );
}
CPE = "cpe:/a:samsung:allshare:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_remote_headers( port: port );
if(IsMatchRegexp( buf, "SERVER\\s*:\\s*(UPnP/[0-9]\\.[0-9]\\s*)?Samsung Allshare Server" )){
	set_kb_item( name: "samsung/allshare/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "Samsung AllShare Server/([0-9.]+)" );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	register_and_report_cpe( app: "Samsung AllShare Server", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

