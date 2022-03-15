if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143232" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-06 08:21:59 +0000 (Fri, 06 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "FreeSWITCH Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of FreeSWITCH over HTTP.

  This script performs HTTP based detection of FreeSWITCH." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 8181 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/api/version";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "FreeSWITCH Version" )){
	set_kb_item( name: "freeswitch/detected", value: TRUE );
	set_kb_item( name: "freeswitch/http/port", value: port );
	version = "unknown";
	vers = eregmatch( pattern: "FreeSWITCH Version ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "freeswitch/http/" + port + "/concUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		set_kb_item( name: "freeswitch/http/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "freeswitch/http/" + port + "/version", value: version );
}
exit( 0 );

