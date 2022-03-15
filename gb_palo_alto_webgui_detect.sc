if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105261" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-22 13:08:50 +0200 (Wed, 22 Apr 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Palo Alto Device Detection (Web UI)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request
  to the server and attempts to detect the Web UI for Palo Alto devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
res = http_get_cache( item: "/php/login.php", port: port );
if(ContainsString( banner, "Server: PanWeb Server/" ) || ( ContainsString( res, "Pan.base.cookie.set" ) && ContainsString( res, "BEGIN PAN_FORM_CONTENT" ) ) || ( ContainsString( res, "'js/Pan.js'></script>" ) && ( ContainsString( res, "/login/images/logo-pan-" ) || ContainsString( res, "/images/login-page.gif" ) ) )){
	fw_version = "unknown";
	model = "unknown";
	set_kb_item( name: "palo_alto/detected", value: TRUE );
	set_kb_item( name: "palo_alto/webui/detected", value: TRUE );
	set_kb_item( name: "palo_alto/webui/port", value: port );
	set_kb_item( name: "palo_alto/webui/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "palo_alto/webui/" + port + "/model", value: model );
	set_kb_item( name: "palo_alto/webui/" + port + "/concluded", value: "HTTP(s) Login Page" );
}
exit( 0 );

