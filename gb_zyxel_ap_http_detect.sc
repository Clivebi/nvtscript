if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142867" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-09-10 02:16:55 +0000 (Tue, 10 Sep 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Zyxel Access Point Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Zyxel Access Points

  The script sends a connection request to the server and attempts to detect Zyxel Access Point devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.zyxel.com/products_services/smb-wlan_aps_and_controllers.shtml?t=c" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(( ContainsString( res, "_Enter_User" ) || ContainsString( res, "col_model_info" ) ) && ( ContainsString( res, "zld_product_spec.js" ) || IsMatchRegexp( res, "<title>(USG|NXC|ZyWALL )[0-9]+" ) )){
	version = "unknown";
	hw_name = "Zyxel Access Point ";
	mod = eregmatch( pattern: "name=\"model\">([^<]+)<", string: res );
	if( !isnull( mod[1] ) ){
		hw_name += mod[1];
		cpe_model = str_replace( string: mod[1], find: " ", replace: "" );
		hw_cpe = "cpe:/h:zyxel:" + tolower( cpe_model );
		os_cpe = "cpe:/o:zyxel:" + tolower( cpe_model ) + "_firmware";
	}
	else {
		mod = eregmatch( pattern: "model_title\" >([^<]+)<", string: res );
		if( !isnull( mod[1] ) ){
			hw_name += mod[1];
			cpe_model = str_replace( string: mod[1], find: " ", replace: "" );
			hw_cpe = "cpe:/h:zyxel:" + tolower( cpe_model );
			os_cpe = "cpe:/o:zyxel:" + tolower( cpe_model ) + "_firmware";
		}
		else {
			hw_name += "Unknown Model";
			hw_cpe = "cpe:/h:zyxel:access_point";
			os_cpe = "cpe:/o:zyxel:access_point_firmware";
		}
	}
	set_kb_item( name: "zyxel_ap/detected", value: TRUE );
	os_register_and_report( os: hw_name + " Firmware", cpe: os_cpe, port: port, desc: "Zyxel Access Point Detection (HTTP)", runs_key: "unixoide" );
	register_product( cpe: os_cpe, location: "/", port: port, service: "www" );
	register_product( cpe: hw_cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: hw_name, version: version, install: "/", cpe: hw_cpe ), port: port );
	exit( 0 );
}
exit( 0 );

