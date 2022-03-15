if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114042" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-05 18:28:04 +0100 (Mon, 05 Nov 2018)" );
	script_name( "March Networks VisionWEB Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8001 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of March
  Networks VisionWEB.

  This script sends an HTTP GET request and tries to ensure the presence of
  March Networks VisionWEB." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8001 );
url = "/visionweb/index2.html";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<meta name=\"DESCRIPTION\" content=\"VisionWEB. March Networks SpA" ) && ContainsString( res, "March Networks S.p.A.\"" )){
	version = "unknown";
	set_kb_item( name: "march_networks/visionweb/detected", value: TRUE );
	set_kb_item( name: "march_networks/visonweb/" + port + "/detected", value: TRUE );
	vers = eregmatch( pattern: "codebase=\"NettunoVisionWEB.cab#version=([0-9]+),([0-9]+),([0-9]+),([0-9]+)\"", string: res );
	if(!isnull( vers[1] ) && !isnull( vers[2] ) && !isnull( vers[3] ) && !isnull( vers[4] )){
		version = vers[1] + "." + vers[2] + "." + vers[3] + "." + vers[4];
	}
	set_kb_item( name: "march_networks/visonweb/version", value: version );
	cpe = "cpe:/a:march_networks:visionweb:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "March Networks VisionWEB", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, conclUrl: conclUrl );
}
exit( 0 );

