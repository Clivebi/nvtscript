if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804608" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-06-02 09:14:12 +0530 (Mon, 02 Jun 2014)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "BarracudaDrive Version Detection" );
	script_tag( name: "summary", value: "Detection of BarracudaDrive.

This script sends an HTTP GET request and tries to get the version from the
response." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
http_port = http_get_port( default: 80 );
bdReq = http_get( item: "/rtl/about.lsp", port: http_port );
bdRes = http_send_recv( port: http_port, data: bdReq );
if(ContainsString( bdRes, ">BarracudaDrive" )){
	bdVer = eregmatch( pattern: "(>Version|>BarracudaDrive|>BarracudaDrive.[v|V]ersion:).([0-9.]+)<", string: bdRes );
	if(bdVer[2]){
		set_kb_item( name: "www/" + http_port + "/BarracudaDrive", value: bdVer[2] );
		set_kb_item( name: "BarracudaDrive/Installed", value: TRUE );
		cpe = build_cpe( value: bdVer[2], exp: "^([0-9.]+)", base: "cpe:/a:barracudadrive:barracudadrive:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:barracudadrive:barracudadrive";
		}
		register_product( cpe: cpe, location: http_port + "/tcp", port: http_port, service: "www" );
		log_message( data: build_detection_report( app: "BarracudaDrive", version: bdVer[2], install: http_port + "/tcp", cpe: cpe, concluded: bdVer[2] ), port: http_port );
	}
}

