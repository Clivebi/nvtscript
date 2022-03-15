if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810306" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-09 12:11:43 +0530 (Fri, 09 Dec 2016)" );
	script_name( "Red Hat JBoss EAP Server Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of installed version
  of Red Hat JBoss EAP Server.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "JBoss-EAP/banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(!concl = egrep( string: banner, pattern: "Server: JBoss-EAP", icase: TRUE )){
	exit( 0 );
}
concl = chomp( concl );
install = "/";
version = "unknown";
vers = eregmatch( pattern: "Server: JBoss-EAP/([0-9.]+)", string: banner );
if(vers[1]){
	version = vers[1];
	concl = vers[0];
}
set_kb_item( name: "www/" + port + "/", value: version );
set_kb_item( name: "Redhat/JBoss/EAP/Installed", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:redhat:jboss_enterprise_application_platform:" );
if(!cpe){
	cpe = "cpe:/a:redhat:jboss_enterprise_application_platform";
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "Red Hat JBoss EAP", version: version, install: install, cpe: cpe, concluded: concl ), port: port );
exit( 0 );

