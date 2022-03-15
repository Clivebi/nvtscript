CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108105" );
	script_version( "2020-05-08T10:38:28+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 10:38:28 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2017-03-23 09:57:33 +0100 (Thu, 23 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Kunena Forum Extension for Joomla Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "summary", value: "Detection of the Kunena forum extension for Joomla.

  The script sends a HTTP request to the server and attempts to extract the version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
install = dir;
if(dir == "/"){
	dir = "";
}
url = dir + "/plugins/kunena/kunena/kunena.xml";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
urls = dir + "/plugins/system/kunena/kunena.xml";
req2 = http_get( item: urls, port: port );
res2 = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "<name>plg_kunena_kunena</name>" ) || ContainsString( res2, "<name>plg_kunena_kunena</name>" )){
	version = "unknown";
	ver = eregmatch( pattern: "<version>([0-9.]+)</version>", string: res );
	if( !isnull( ver[1] ) ){
		version = ver[1];
		conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
	}
	else {
		ver = eregmatch( pattern: "<version>([0-9.]+)</version>", string: res2 );
		if(!isnull( ver[1] )){
			version = ver[1];
			conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
		}
	}
	set_kb_item( name: "www/" + port + "/kunena_forum", value: version );
	set_kb_item( name: "kunena_forum/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kunena:kunena:" );
	if(!cpe){
		cpe = "cpe:/a:kunena:kunena";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Kunena Forum Extension", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
}
exit( 0 );

