if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114033" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-09-17 12:00:40 +0200 (Mon, 17 Sep 2018)" );
	script_name( "Cisco TelePresence Codec Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Cisco TelePresence Codec.

  This script sends an HTTP GET request and tries to ensure the presence of
  Cisco TelePresence Codec." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/web/signin";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "The resource could not be found.<br />" )){
	url = "/web/sessions/new";
	res = http_get_cache( port: port, item: url );
}
if(IsMatchRegexp( res, "<link href=\"/static/vega.[0-9a-zA-Z]+.min.css\" media=\"screen\" rel=\"stylesheet\" type=\"text/css\" />" ) && IsMatchRegexp( res, "<script src=\"/static/vega.[0-9a-zA-Z]+.min.js\" type=\"text/javascript\"></script>" )){
	version = "unknown";
	set_kb_item( name: "cisco/telepresence/codec/detected", value: TRUE );
	set_kb_item( name: "cisco/telepresence/codec/" + port + "/detected", value: TRUE );
	cpe = "cpe:/a:cisco:telepresence_codec:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "Cisco TelePresence Codec", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, conclUrl: conclUrl, extra: "Login required for version/model detection." );
}
exit( 0 );

