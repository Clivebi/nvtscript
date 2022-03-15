if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103753" );
	script_version( "2021-07-28T08:40:06+0000" );
	script_tag( name: "last_modification", value: "2021-07-28 08:40:06 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-08-08 17:20:17 +0200 (Thu, 08 Aug 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Seagate BlackArmor NAS Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Seagate BlackArmor NAS devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.seagate.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/index.php" );
if(( !ContainsString( res, "<title>Seagate NAS" ) || !ContainsString( res, "p_user" ) ) && !ContainsString( res, "Login to BlackArmor" )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
install = "/";
set_kb_item( name: "seagate/blackarmor_nas/detected", value: TRUE );
set_kb_item( name: "seagate/blackarmor_nas/http/detected", value: TRUE );
mod = eregmatch( pattern: "Seagate NAS - ([0-9A-Z-]+)", string: res );
if(!isnull( mod[1] )){
	model = mod[1];
}
os_name = "Seagate BlackArmor NAS ";
hw_name = os_name;
if( model != "unknown" ){
	os_name += model + " Firmware";
	hw_name += model;
	cpe_model = tolower( str_replace( string: model, find: "-", replace: "_" ) );
	os_cpe = "cpe:/o:seagate:blackarmor_" + cpe_model + "_firmware";
	hw_cpe = "cpe:/h:seagate:blackarmor_" + cpe_model;
}
else {
	os_name += "Firmware";
	hw_name += "Unknown Model";
	os_cpe = "cpe:/o:seagate:blackarmor_nas_firmware";
	hw_cpe = "cpe:/h:seagate:blackarmor_nas";
}
os_register_and_report( os: os_name, cpe: os_cpe, desc: "Seagate BlackArmor NAS Detection (HTTP)", runs_key: "unixoide" );
register_product( cpe: os_cpe, location: "/", port: port, service: "www" );
register_product( cpe: hw_cpe, location: "/", port: port, service: "www" );
report = build_detection_report( app: os_name, version: version, install: install, cpe: os_cpe );
report += "\n\n";
report += build_detection_report( app: hw_name, skip_version: TRUE, install: install, cpe: hw_cpe );
log_message( port: port, data: report );
exit( 0 );

