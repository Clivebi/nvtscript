if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805714" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-07-07 15:16:06 +0530 (Tue, 07 Jul 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ManageEngine Password Manager Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  ManageEngine Password Manager pro.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7272 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
mePort = http_get_port( default: 7272 );
req = http_get( item: "/PassTrixMain.cc", port: mePort );
res = http_keepalive_send_recv( port: mePort, data: req );
if(ContainsString( res, "<title>ManageEngine Password Manager Pro</title>" ) && ContainsString( res, "PMP_User_Locale" ) && ContainsString( res, "ZOHO Corp" )){
	meVer = eregmatch( pattern: "/themes/passtrix/V([0-9]+)", string: res );
	if( !meVer[1] ){
		meVer = "Unknown";
	}
	else {
		meVer = meVer[1];
	}
	tmp_version = "Build version " + meVer;
	set_kb_item( name: "www/" + mePort + "/", value: meVer );
	set_kb_item( name: "ManageEngine/Password_Manager/installed", value: TRUE );
	cpe = build_cpe( value: meVer, exp: "^([0-9]+)", base: "cpe:/a:manageengine:password_manager_pro:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:manageengine:password_manager_pro";
	}
	register_product( cpe: cpe, location: "/", port: mePort, service: "www" );
	log_message( data: build_detection_report( app: "ManageEngine Password Manager", version: meVer, install: "/", cpe: cpe, concluded: tmp_version ), port: mePort );
}
exit( 0 );

