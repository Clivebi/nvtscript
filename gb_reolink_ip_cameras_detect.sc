if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114102" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-02 02:10:57 +0000 (Tue, 02 Jul 2019)" );
	script_name( "Reolink IP Cameras Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of
  Reolink IP Cameras.

  This script sends an HTTP GET request and tries to ensure the presence of
  a Reolink IP Camera." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://reolink.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/cgi-bin/api.cgi";
req = http_post_put_req( port: port, url: url, data: "" );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "\"cmd\"\\s*:\\s*\"Unknown\"," ) && IsMatchRegexp( res, "\"detail\"\\s*:\\s*\"please login first\"," )){
	version = "unknown";
	res = http_get_cache( port: port, item: "/js/client.config.js" );
	ver = eregmatch( pattern: "\"version\":\\s*\"v([0-9.]+)\"", string: res );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	set_kb_item( name: "reolink/ip_camera/detected", value: TRUE );
	cpe = "cpe:/h:reolink:ip_camera:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "Reolink IP Camera", ver: version, concluded: ver[0], base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl );
}
exit( 0 );

