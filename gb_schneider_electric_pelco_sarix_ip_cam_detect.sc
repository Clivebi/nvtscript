if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813064" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-03 14:44:14 +0530 (Tue, 03 Apr 2018)" );
	script_name( "Schneider Electric Pelco Sarix IP Camera Remote Detection" );
	script_tag( name: "summary", value: "Detection of presence of Schneider
  Electric Pelco Sarix IP Camera.

  The script sends a HTTP GET connection request to the server and attempts
  to determine if the remote host runs Electric Pelco Sarix IP Camera from
  the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
ipPort = http_get_port( default: 80 );
res = http_get_cache( port: ipPort, item: "/liveview" );
if(IsMatchRegexp( res, "<span>[Ss]arix&[Tt]rade;</span>" ) && IsMatchRegexp( res, "<span>Copyright\\s*&copy;\\s*[0-9]+-[0-9]+,\\s*[Pp][Ee][Ll][Cc][Oo]\\s*&middot;" ) || ContainsString( res, "Sarix&trade;" ) && ContainsString( res, "tooltip.js\"></script>" ) && ContainsString( res, "cookie.js\"></script>" )){
	version = "unknown";
	install = "/";
	set_kb_item( name: "Schneider_Electric/Pelco_Sarix/IP_Camera/installed", value: TRUE );
	cpe = "cpe:/a:schneider_electric:pelco_sarix_professional";
	register_product( cpe: cpe, location: install, port: ipPort, service: "www" );
	log_message( data: build_detection_report( app: "Schneider Electric Pelco Sarix IP Camera", version: version, install: install, cpe: cpe, concluded: version ), port: ipPort );
	exit( 0 );
}
exit( 0 );

