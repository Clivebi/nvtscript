if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105748" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-01 15:50:24 +0200 (Wed, 01 Jun 2016)" );
	script_name( "IBM Security Network Protection Web Interface Detection" );
	script_tag( name: "summary", value: "This script detects the IBM Security Network Protection web interface" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/login";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>IBM Security Network Protection</title>" ) || !ContainsString( buf, "IBM Corporation" ) || !ContainsString( buf, "login_form_password" )){
	exit( 0 );
}
register_product( cpe: "cpe:/a:ibm:security_network_protection", location: "/login", port: port, service: "www" );
log_message( port: port, data: "The IBM Security Network Protection Web Interface is running at this port.\nCPE: cpe:/a:ibm:security_network_protection" );
exit( 0 );

