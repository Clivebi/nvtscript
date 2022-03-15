if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114038" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-09 19:01:40 +0200 (Tue, 09 Oct 2018)" );
	script_name( "Xiongmai Net Surveillance Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of Xiongmai
  Net Surveillance.

  This script sends an HTTP GET request and tries to ensure the presence of
  Xiongmai Net Surveillance." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url1 = "/Login.htm";
res1 = http_get_cache( port: port, item: url1 );
url2 = "/English.js";
res2 = http_get_cache( port: port, item: url2 );
url3 = "/";
res3 = http_get_cache( port: port, item: url3 );
if(( ContainsString( res1, "Hash.Cookie('NetSuveillanceWebCookie'" ) && ContainsString( res1, "$('passWordInput').setText(Translate.pswd);" ) && ContainsString( res2, "title:\"Digital Video Recorder\"" ) && ContainsString( res2, "MFt:\"MainStream\"" ) ) || ContainsString( res3, "<title>NETSurveillance WEB</title>" )){
	version = "unknown";
	set_kb_item( name: "xiongmai/net_surveillance/detected", value: TRUE );
	set_kb_item( name: "xiongmai/net_surveillance/" + port + "/detected", value: TRUE );
	url4 = "/DVR.htm";
	res4 = http_get_cache( port: port, item: url4 );
	if(ContainsString( res4, "g_SoftWareVersion=" ) && ( ContainsString( res4, "div id=\"playView\"" ) || ContainsString( res4, "<div id=\"MessageBox\">" ) )){
		ver = eregmatch( pattern: "g_SoftWareVersion=\"V([0-9.a-zA-Z]+)\"", string: res4 );
		if(!isnull( ver[1] )){
			version = ver[1];
			set_kb_item( name: "xiongmai/net_surveillance/version", value: version );
			set_kb_item( name: "xiongmai/net_surveillance/" + port + "/auth_bypass_possible", value: TRUE );
		}
	}
	cpe = "cpe:/a:xiongmai:net_surveillance:";
	conclUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
	if(version == "unknown"){
		extra = "Login required for version detection.";
	}
	register_and_report_cpe( app: "Xiongmai Net Surveillance", ver: version, base: cpe, expr: "^([0-9.a-z]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl, extra: extra );
}
exit( 0 );

