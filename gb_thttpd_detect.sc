if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140800" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-23 10:46:04 +0700 (Fri, 23 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "thttpd Detection" );
	script_tag( name: "summary", value: "Detection of thttpd.

  The script sends a connection request to the server and attempts to detect thttpd and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "thttpd/banner" );
	script_xref( name: "URL", value: "https://acme.com/software/thttpd/" );
	exit( 0 );
}
CPE = "cpe:/a:acme:thttpd:";
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: thttpd/" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "thttpd/([0-9a-z.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: "thttpd/detected", value: TRUE );
register_and_report_cpe( app: "thttpd", ver: version, concluded: vers[0], base: CPE, expr: "([0-9a-z.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
exit( 0 );

