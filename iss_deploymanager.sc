if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17585" );
	script_version( "2021-03-19T09:23:16+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 09:23:16 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ISS Deployment Manager Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3994 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the ISS Deployment Manager." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 3994 );
url = "/deploymentmanager/index.jsp";
res = http_get_cache( item: url, port: port );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "<title>SiteProtector</title>" ) && egrep( pattern: "Welcome to SiteProtector Deployment Manager", string: res )){
	log_message( port: port );
}
exit( 0 );

