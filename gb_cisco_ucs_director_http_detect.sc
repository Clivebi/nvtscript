if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105576" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-09-23T09:17:45+0000" );
	script_tag( name: "last_modification", value: "2020-09-23 09:17:45 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "creation_date", value: "2016-03-17 16:05:49 +0100 (Thu, 17 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco UCS Director Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Cisco UCS Director." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/app/ui/login.jsp";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>Login</title>" ) || !ContainsString( buf, ">Cisco UCS Director<" ) || !ContainsString( buf, "Cisco Systems, Inc." )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "cisco/ucs_director/detected", value: TRUE );
set_kb_item( name: "cisco/ucs_director/http/port", value: port );
set_kb_item( name: "cisco/ucs_director/http/" + port + "/version", value: version );
set_kb_item( name: "cisco/ucs_director/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
exit( 0 );

