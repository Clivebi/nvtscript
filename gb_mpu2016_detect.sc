if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103893" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-01-27 18:43:12 +0100 (Mon, 27 Jan 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Emerson Network Power Avocent MergePoint Unity 2016 KVM Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/login.php", port: port );
if(!ContainsString( buf, "<title>MPU2016 Explorer" )){
	exit( 0 );
}
vers = "unknown";
install = "/";
version = eregmatch( pattern: "Appliance firmware version ([0-9.]+)", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
}
set_kb_item( name: "MPU2016/installed", value: TRUE );
cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/h:emerson:network_power_avocent_mergepoint_unity_2016_firmware:" );
if(isnull( cpe )){
	cpe = "cpe:/h:emerson:network_power_avocent_mergepoint_unity_2016_firmware";
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "Emerson Network Power Avocent MergePoint Unity 2016 KVM", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

