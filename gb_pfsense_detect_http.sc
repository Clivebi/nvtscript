if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806807" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-01-14 18:46:02 +0530 (Thu, 14 Jan 2016)" );
	script_name( "pfSense Detection (HTTP(s))" );
	script_tag( name: "summary", value: "Detection of installed version
  of pfSense.

  This script sends an HTTP GET request, tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
pfsPort = http_get_port( default: 443 );
rcvRes = http_get_cache( item: "/", port: pfsPort );
if(ContainsString( rcvRes, "pfsense" ) && ( ContainsString( rcvRes, ">Login to pfSense<" ) || ContainsString( rcvRes, "/themes/pfsense_ng" ) || ContainsString( rcvRes, "<title id=\"pfsense-logo-svg\">pfSense Logo</title>" ) )){
	set_kb_item( name: "pfsense/installed", value: TRUE );
	set_kb_item( name: "pfsense/http/installed", value: TRUE );
	set_kb_item( name: "pfsense/http/port", value: pfsPort );
	vers = "unknown";
}
exit( 0 );

