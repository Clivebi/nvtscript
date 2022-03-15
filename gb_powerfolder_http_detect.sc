if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107009" );
	script_version( "2021-04-28T09:53:57+0000" );
	script_tag( name: "last_modification", value: "2021-04-28 09:53:57 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-06-07 06:40:16 +0200 (Tue, 07 Jun 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PowerFolder Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of PowerFolder." );
	script_xref( name: "URL", value: "https://www.powerfolder.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/login";
res = http_get_cache( port: port, item: url );
banner = http_get_remote_headers( port: port );
if(( IsMatchRegexp( banner, "PF-Server-(Name|ID)\\s*:.+" ) && ContainsString( res, "name=\"label_clients\"" ) ) || ( ContainsString( res, "powerfolder/util.js" ) && ContainsString( res, "Please enable Javascript to use PowerFolder properly" ) ) || ( IsMatchRegexp( res, "<a href=\"https?://(www\\.)?powerfolder\\.com\"" ) && ContainsString( res, "name=\"label_powered_by\"" ) )){
	version = "unknown";
	vers = eregmatch( pattern: "Program version: ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "powerfolder/detected", value: TRUE );
	set_kb_item( name: "powerfolder/http/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:powerfolder:powerfolder:" );
	if(!cpe){
		cpe = "cpe:/a:powerfolder:powerfolder";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "PowerFolder", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

