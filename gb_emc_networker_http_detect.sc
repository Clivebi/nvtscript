if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103124" );
	script_version( "2021-09-29T09:55:16+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 09:55:16 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-03-23 13:28:27 +0100 (Wed, 23 Mar 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell EMC NetWorker Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Dell EMC NetWorker." );
	script_xref( name: "URL", value: "https://www.delltechnologies.com/en-us/data-protection/data-protection-suite/networker-data-protection-software.htm" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 9000 );
res = http_get_cache( port: port, item: "/" );
if(egrep( pattern: "<title>Welcome to NetWorker Management Console", string: res, icase: TRUE )){
	version = "unknown";
	url = "/buttons.html";
	res = http_get_cache( port: port, item: url );
	vers = eregmatch( pattern: "NetWorker v([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "emc/networker/detected", value: TRUE );
	set_kb_item( name: "emc/networker/http/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:emc:networker:" );
	if(!cpe){
		cpe = "cpe:/a:emc:networker";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dell EMC NetWorker", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
}
exit( 0 );

