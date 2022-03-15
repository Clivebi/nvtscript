if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114077" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-27 13:40:02 +0100 (Wed, 27 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "TP-Link Megapixel Surveillance Camera Detection" );
	script_tag( name: "summary", value: "Detection of Megapixel Surveillance Camera.

  The script sends a connection request to the server and attempts to detect the web interface for TP-Link's Megapixel Surveillance Camera." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.tp-link.com/download/TL-SC3430N.html#Firmware" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/prod";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "Megapixel Surveillance Camera" ) && IsMatchRegexp( res, "initProdNbr=\"[^\"]+\"" )){
	version = "unknown";
	install = "/";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	model = eregmatch( pattern: "initProdNbr=\"([^\"]+)\"", string: res, icase: TRUE );
	if(!isnull( model[1] )){
		set_kb_item( name: "tp-link/wireless/megapixel_surveillance_camera/model", value: model[1] );
	}
	set_kb_item( name: "tp-link/wireless/megapixel_surveillance_camera/detected", value: TRUE );
	set_kb_item( name: "tp-link/wireless/megapixel_surveillance_camera/" + port + "/detected", value: TRUE );
	cpe = "cpe:/h:tp-link:megapixel_surveillance_camera";
	register_and_report_cpe( app: "TP-Link Megapixel Surveillance Camera", ver: version, concluded: "TP-Link Megapixel Surveillance Camera " + model[1], base: cpe, expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www", conclUrl: conclUrl, extra: "Version detection requires login." );
}
exit( 0 );

