if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141467" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-09-11 10:50:41 +0700 (Tue, 11 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Monit Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Monit.

  The script sends a connection request to the server and attempts to detect Monit and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080, 8181 );
	script_mandatory_keys( "monit/banner" );
	script_xref( name: "URL", value: "https://mmonit.com/monit/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
res = http_get_cache( port: port, item: "/" );
if(!IsMatchRegexp( banner, "Server\\s*:\\s*monit" ) && !IsMatchRegexp( banner, "WWW-Authenticate\\s*:\\s*Basic\\s+realm=\"monit\"" ) && !ContainsString( res, "You are not authorized to access monit." ) && !IsMatchRegexp( res, "https?://(www\\.)?mmonit\\.com/monit" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "Server\\s*:\\s*monit ([0-9.]+)", string: banner, icase: TRUE );
if(!isnull( vers[1] )){
	version = vers[1];
	concluded = vers[0];
}
if(version == "unknown"){
	vers = eregmatch( pattern: ">monit ([0-9.]+)<", string: res, icase: FALSE );
	if(!isnull( vers[1] )){
		version = vers[1];
		concluded = vers[0];
	}
}
if(version == "unknown"){
	concl = egrep( pattern: "(Server\\s*:\\s*monit|WWW-Authenticate\\s*:\\s*Basic\\s+realm=\"monit\")", string: banner, icase: TRUE );
	if(concl){
		concluded = concl;
	}
}
set_kb_item( name: "monit/detected", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tildeslash:monit:" );
if(!cpe){
	cpe = "cpe:/a:tildeslash:monit";
}
os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: "HTTP banner / authorization header", desc: "Monit Detection (HTTP)", runs_key: "unixoide" );
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Monit", version: version, install: "/", cpe: cpe, concluded: concluded ), port: port );
exit( 0 );

