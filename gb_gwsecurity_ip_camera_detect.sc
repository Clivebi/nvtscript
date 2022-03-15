if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114082" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-14 13:23:37 +0100 (Thu, 14 Mar 2019)" );
	script_name( "GW Security IP Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of
  GW Security's IP Camera software.

  This script sends an HTTP GET request and tries to ensure the presence of
  the GW Security IP Camera web interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url1 = "/doc/xml/en/Preview.xml";
url2 = "/doc/xml/en/Login.xml";
res1 = http_get_cache( port: port, item: url1 );
res2 = http_get_cache( port: port, item: url2 );
if(ContainsString( res1, "<laMainStream>Record Bitrate</laMainStream>" ) && ContainsString( res1, "<laSubStream>Network Bitrate</laSubStream>" ) && ContainsString( res2, "<LoginTips1>Please" ) && ContainsString( res2, "<LoginTips2>User name cannot be longer than 16 characters.</LoginTips2>" )){
	version = "unknown";
	set_kb_item( name: "gw_security/ip_camera/detected", value: TRUE );
	set_kb_item( name: "gw_security/ip_camera/" + port + "/detected", value: TRUE );
	cpe = "cpe:/a:gw_security:ip_camera:";
	conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
	register_and_report_cpe( app: "GW Security IP Camera", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl, extra: "Version detection requires login." );
}
exit( 0 );

