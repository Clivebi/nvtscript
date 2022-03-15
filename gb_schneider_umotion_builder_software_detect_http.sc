if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107448" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-12 15:02:52 +0100 (Sat, 12 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Schneider Electric U.motion Builder Software Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Schneider Electric U.motion Builder Software

  The script sends an HTTP connection request to the server and attempts to detect Schneider Electric U.motion
  Builder Softwaret and to extract its version." );
	script_xref( name: "URL", value: "https://www.schneider-electric.com/en/product-range/61124-u.motion/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/umotion/modules/system/externalframe.php?context=runtime";
buf = http_get_cache( item: url, port: port );
if(ContainsString( buf, "U.motion</title>" ) && ContainsString( buf, "U.motion Control" )){
	version = "unknown";
	vers = eregmatch( pattern: "\"version\":\"([0-9.]+)\"", string: buf );
	if(!isnull( vers[1] )){
		version = vers[1];
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "schneider/umotion_builder/detected", value: TRUE );
	register_and_report_cpe( app: "Schneider Electric U.motion Builder Software", ver: version, base: "cpe:/a:schneider-electric:u.motion_builder:", expr: "^([0-9.]+)", insloc: "/umotion", regPort: port, concluded: vers[0], conclUrl: conclUrl, regService: "www" );
}
exit( 0 );

