if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18532" );
	script_version( "2021-02-26T10:28:36+0000" );
	script_tag( name: "last_modification", value: "2021-02-26 10:28:36 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Enterasys Dragon Enterprise Reporting Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Enterasys Dragon Enterprise Reporting." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9443 );
res = http_get_cache( item: "/dragon/login.jsp", port: port );
if(res && ContainsString( res, ">Dragon Enterprise Reporting<" )){
	version = "unknown";
	cpe = "cpe:/a:enterasys:dragon_enterprise_reporting";
	register_and_report_cpe( app: "Enterasys Dragon Enterprise Reporting", ver: version, base: cpe, expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

