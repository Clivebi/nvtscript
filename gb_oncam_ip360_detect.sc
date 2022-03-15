if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114093" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-30 13:02:37 +0200 (Tue, 30 Apr 2019)" );
	script_name( "Oncam IP 360 Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of
  Oncam IP 360.

  This script sends an HTTP GET request and tries to ensure the presence of
  the Oncam IP 360 web interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<link href=\"/oncam.ico\"" ) && ContainsString( res, "WWW-Authenticate: Basic realm=IP Camera" )){
	version = "unknown";
	set_kb_item( name: "oncam/ip360/detected", value: TRUE );
	verUrl = "/admin/getparam.cgi?softwareversion";
	res2 = http_get_cache( port: port, item: verUrl );
	ver = eregmatch( pattern: "softwareversion=([0-9.]+[a-zA-Z]*)", string: res2, icase: TRUE );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	cpe = "cpe:/a:oncam:ip360:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "Oncam IP 360", ver: version, concluded: ver[0], base: cpe, expr: "^([0-9.]+[a-zA-Z]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl );
}
exit( 0 );

