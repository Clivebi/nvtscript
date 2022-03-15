if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100543" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-19 11:14:17 +0100 (Fri, 19 Mar 2010)" );
	script_name( "AlienVault OSSIM Detection" );
	script_tag( name: "summary", value: "Detects the installed version of AlienVault OSSIM (Open Source Security
  Information Management) and USM (Unified Security Management)

  This script sends an HTTP GET request and tries to get the version from the response." );
	script_xref( name: "URL", value: "http://www.alienvault.com" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/ossim", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/session/login.php";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: "<title> AlienVault.*Open Source (SIM|SIEM)", string: buf, icase: FALSE ) || egrep( pattern: "<title> OSSIM Framework Login", string: buf, icase: FALSE ) || IsMatchRegexp( buf, "<title>AlienVault (USM|OSSIM)" )){
		if( IsMatchRegexp( buf, "<title>AlienVault USM" ) ){
			model = "USM";
			cpe = "cpe:/a:alienvault:unified_security_management";
		}
		else {
			model = "OSSIM";
			cpe = "cpe:/a:alienvault:open_source_security_information_management";
		}
		vers = "unknown";
		set_kb_item( name: "OSSIM/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "AlienVault " + model, version: vers, install: install, cpe: cpe, concluded: vers ), port: port );
	}
}
exit( 0 );

