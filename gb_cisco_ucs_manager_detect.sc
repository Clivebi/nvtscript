if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103804" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-10 18:42:38 +0200 (Thu, 10 Oct 2013)" );
	script_name( "Cisco UCS Manager Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/", port: port );
if(!ContainsString( buf, "<title>Cisco UCS Manager</title>" ) || ( !ContainsString( buf, "UCS Manager requires Java" ) && !ContainsString( buf, "Cisco Unified Computing System (UCS) Manager" ) && !ContainsString( buf, "Launch UCS Manager" ) )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "<p class=\"version\">Version ([^<]+)</p>", string: buf );
if(isnull( vers[1] )){
	vers = eregmatch( pattern: "<span class=\"version pull-right\">([^<]+)</span>", string: buf );
}
if(isnull( vers[1] )){
	vers = eregmatch( pattern: "<h1>Cisco UCS Manager - ([^<]+)</h1>", string: buf );
}
if(isnull( vers[1] )){
	vers = eregmatch( pattern: "<span class=\"version spanCenter\">([^<]+)</span>", string: buf );
}
if(isnull( vers[1] )){
	vers = eregmatch( pattern: "href=\"app/([0-9]+[0-9a-z_]+)/kvmlauncher.html\"", string: buf );
}
if(!isnull( version[1] )){
	version = ereg_replace( string: vers[1], pattern: "([0-9]+)([_])([0-9])([_])(.*)", replace: "\\1.\\3(\\5)" );
}
set_kb_item( name: "cisco_ucs_manager/installed", value: TRUE );
if( version != "unknown" ) {
	cpe = "cpe:/a:cisco:unified_computing_system_software:" + version;
}
else {
	cpe = "cpe:/a:cisco:unified_computing_system_software";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Cisco UCS Manager", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

