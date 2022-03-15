if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106837" );
	script_version( "2021-06-16T14:43:08+0000" );
	script_tag( name: "last_modification", value: "2021-06-16 14:43:08 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-05-30 09:34:27 +0700 (Tue, 30 May 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "VICIdial Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of VICIdial." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.vicidial.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/vicidial/welcome.php" );
if(ContainsString( res, "Agent Login" ) && ContainsString( res, "vicidial/admin.php" ) && ContainsString( res, "Timeclock" )){
	version = "unknown";
	build = "unknown";
	url = "/agc/vicidial.php";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "VERSION: ([0-9a-z.-]+) &nbsp; &nbsp; &nbsp; BUILD: ([0-9-]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	if(!isnull( vers[2] )){
		build = vers[2];
		set_kb_item( name: "vicidial/build", value: build );
	}
	set_kb_item( name: "vicidial/detected", value: TRUE );
	set_kb_item( name: "vicidial/http/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9a-z.-]+)", base: "cpe:/a:vicidial:vicidial:" );
	if(!cpe){
		cpe = "cpe:/a:vicidial:vicidial";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "VICIdial", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: "Build: " + build ), port: port );
	exit( 0 );
}
exit( 0 );

