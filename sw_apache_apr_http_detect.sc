if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111098" );
	script_version( "2021-07-06T06:41:56+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-06 06:41:56 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-05-01 15:35:19 +0200 (Sun, 01 May 2016)" );
	script_name( "Apache APR Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "apache_server_info.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache/server-info/detected" );
	script_tag( name: "summary", value: "HTTP based detection of Apache APR from an exposed /server-info
  status page." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/server-info";
buf = http_get_cache( item: url, port: port );
aprVer = eregmatch( pattern: "Server loaded APR Version:([ /<>a-zA-Z0-9+=\"]+)<tt>([^<]+)</tt>", string: buf );
if(!isnull( aprVer[2] )){
	install = port + "/tcp";
	conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	set_kb_item( name: "Apache/APR/Ver", value: aprVer[2] );
	cpe = build_cpe( value: aprVer[2], exp: "^([0-9.]+)", base: "cpe:/a:apache:portable_runtime:" );
	if(!cpe){
		cpe = "cpe:/a:apache:portable_runtime";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache APR", version: aprVer[2], install: install, cpe: cpe, concludedUrl: conclurl, concluded: aprVer[0] ), port: port );
}
apuVer = eregmatch( pattern: "Server loaded APU Version:([ /<>a-zA-Z0-9+=\"]+)<tt>([^<]+)</tt>", string: buf );
if(!isnull( apuVer[2] )){
	install = port + "/tcp";
	conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	set_kb_item( name: "Apache/APR-Utils/Ver", value: apuVer[2] );
	cpe = build_cpe( value: apuVer[2], exp: "^([0-9.]+)", base: "cpe:/a:apache:apr-util:" );
	if(!cpe){
		cpe = "cpe:/a:apache:apr-util";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Apache APR-Utils", version: apuVer[2], install: install, cpe: cpe, concludedUrl: conclurl, concluded: apuVer[0] ), port: port );
}
exit( 0 );

