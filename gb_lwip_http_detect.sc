if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108825" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-30 07:52:41 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "lwIP TCP/IP Stack Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of the lwIP TCP/IP stack." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "lwIP/banner" );
	script_xref( name: "URL", value: "https://savannah.nongnu.org/projects/lwip" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!banner = http_get_remote_headers( port: port )){
	exit( 0 );
}
if(!match = egrep( string: banner, pattern: "^Server\\s*:\\s*lwIP", icase: TRUE )){
	exit( 0 );
}
set_kb_item( name: "lwip/detected", value: TRUE );
match = chomp( match );
version = "unknown";
vers = eregmatch( string: match, pattern: "Server\\s*:\\s*lwIP/([0-9.]+)", icase: TRUE );
if(vers){
	version = vers[1];
}
register_and_report_cpe( app: "lwIP TCP/IP Stack", ver: version, concluded: match, base: "cpe:/a:lwip_project:lwip:", expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
exit( 0 );

