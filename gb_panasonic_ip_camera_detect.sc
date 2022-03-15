if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114044" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-05 22:37:25 +0100 (Mon, 05 Nov 2018)" );
	script_name( "Panasonic IP Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of Panasonic's
  IP camera software.

  This script sends an HTTP GET request and tries to ensure the presence of
  Panasonic's IP camera software." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/admin/index.html?Language=0";
res = http_get_cache( port: port, item: url );
if(IsMatchRegexp( res, "Basic realm=\"Panasonic [nN]etwork [dD]evice\"" )){
	version = "unknown";
	model = "unknown";
	url2 = "/";
	res2 = http_get_cache( port: port, item: url2 );
	mod = eregmatch( pattern: "(WV-[a-zA-Z0-9]+) (Network Camera|Netzwerk-Kamera)", string: res2 );
	if(!isnull( mod[1] )){
		model = mod[1];
	}
	set_kb_item( name: "panasonic/ip_camera/detected", value: TRUE );
	set_kb_item( name: "panasonic/ip_camera/" + port + "/detected", value: TRUE );
	set_kb_item( name: "panasonic/ip_camera/model", value: model );
	cpe = "cpe:/a:panasonic:ip_camera:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "Panasonic IP Camera", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, conclUrl: conclUrl, extra: "Model: " + model + "; Note: Login required for version detection." );
}
exit( 0 );

