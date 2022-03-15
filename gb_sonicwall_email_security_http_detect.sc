if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103929" );
	script_version( "2021-04-22T06:21:07+0000" );
	script_tag( name: "last_modification", value: "2021-04-22 06:21:07 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-03-28 12:48:51 +0100 (Fri, 28 Mar 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SonicWall Email Security Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of SonicWall Email Security." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/login.html";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<title>Login</title>" ) && ContainsString( res, ">Email Security" ) && IsMatchRegexp( res, "(SonicWall|Dell)" )){
	set_kb_item( name: "sonicwall/email_security/detected", value: TRUE );
	set_kb_item( name: "sonicwall/email_security/http/detected", value: TRUE );
	set_kb_item( name: "sonicwall/email_security/http/port", value: port );
	set_kb_item( name: "sonicwall/email_security/http/" + port + "/concluded_url", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	version = "unknown";
	vers = eregmatch( pattern: "id=\"firmwareVersion\" value=\"([0-9.]+)\"", string: res );
	if(isnull( vers[1] )){
		vers = eregmatch( pattern: "class=\"lefthand\">([0-9.]+)<", string: res );
	}
	if(!isnull( vers[1] )){
		version = vers[1];
		concluded = "\n  " + vers[0];
	}
	set_kb_item( name: "sonicwall/email_security/http/" + port + "/version", value: version );
	mod = eregmatch( pattern: "id=\"modelNumber\" value=\"([^\"]+)\"", string: res );
	if(!isnull( mod[1] ) && mod[1] != ""){
		set_kb_item( name: "sonicwall/email_security/http/" + port + "/model", value: mod[1] );
		concluded += "\n  " + mod[0];
	}
	if(concluded){
		set_kb_item( name: "sonicwall/email_security/http/" + port + "/concluded", value: concluded );
	}
}
exit( 0 );

