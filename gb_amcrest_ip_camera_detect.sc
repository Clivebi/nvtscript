if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114084" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-15 14:31:11 +0100 (Fri, 15 Mar 2019)" );
	script_name( "Amcrest Technologies IP Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of
  Amcrest's IP Camera software.

  This script sends an HTTP GET request and tries to ensure the presence of
  the Amcrest IP Camera web interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/custom_lang/English.txt";
res = http_get_cache( port: port, item: url );
if(IsMatchRegexp( res, "Copyright\\s*[0-9]+\\s*Amcrest\\s*Technologies" ) && ContainsString( res, "w_camera_info" )){
	version = "unknown";
	set_kb_item( name: "amcrest/ip_camera/detected", value: TRUE );
	set_kb_item( name: "amcrest/ip_camera/" + port + "/detected", value: TRUE );
	cpe = "cpe:/a:amcrest:ip_camera:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "Amcrest Technologies IP Camera", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl, extra: "Version detection requires login." );
}
exit( 0 );

