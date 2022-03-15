if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140329" );
	script_version( "2021-07-12T11:29:43+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 11:29:43 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2017-08-28 14:59:29 +0700 (Mon, 28 Aug 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IceWarp Mail Server Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of IceWarp Mail Server." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.icewarp.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url1 = "/webmail/";
url2 = "/webmail/?interface=basic";
banner = http_get_remote_headers( port: port );
res1 = http_get_cache( port: port, item: url1 );
res2 = http_get_cache( port: port, item: url2 );
if(concl = egrep( string: banner, pattern: "^Server\\s*:\\s*IceWarp", icase: TRUE )){
	found = TRUE;
	concl = chomp( concl );
	concl = ereg_replace( string: concl, pattern: "^(\\s+)", replace: "" );
	concluded += "    " + concl;
}
if(concl = egrep( string: res1, pattern: "(^\\s*<title>IceWarp Web[^<]+</title>|>IceWarp Server</a> &copy;|<base href=.+/-\\.\\._\\._\\.--\\.\\._[0-9]+/webmail/)", icase: FALSE )){
	found = TRUE;
	if(concluded){
		concluded += "\n";
	}
	concl = chomp( concl );
	concl = ereg_replace( string: concl, pattern: "^(\\s+)", replace: "" );
	concluded += "    " + concl;
	conclUrl = "    " + http_report_vuln_url( port: port, url: url1, url_only: TRUE );
}
if(concl = egrep( string: res2, pattern: "(^\\s*<title>IceWarp Web[^<]+</title>|>IceWarp Server</a> &copy;|<base href=.+/-\\.\\._\\._\\.--\\.\\._[0-9]+/webmail/)", icase: FALSE )){
	found = TRUE;
	if(concluded){
		concluded += "\n";
	}
	concl = chomp( concl );
	concl = ereg_replace( string: concl, pattern: "^(\\s+)", replace: "" );
	concluded += "    " + concl;
	if(conclUrl){
		conclUrl += "\n";
	}
	conclUrl += "    " + http_report_vuln_url( port: port, url: url2, url_only: TRUE );
}
if(found){
	version = "unknown";
	set_kb_item( name: "icewarp/mailserver/detected", value: TRUE );
	set_kb_item( name: "icewarp/mailserver/http/detected", value: TRUE );
	set_kb_item( name: "icewarp/mailserver/http/port", value: port );
	set_kb_item( name: "icewarp/mailserver/http/" + port + "/concluded", value: concluded );
	if(conclUrl){
		set_kb_item( name: "icewarp/mailserver/http/" + port + "/concludedUrl", value: conclUrl );
	}
	vers = eregmatch( pattern: "Server\\s*:\\s*IceWarp/([0-9.]+)", string: banner, icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	if(version == "unknown"){
		vers = eregmatch( pattern: "<div id=\"foot_copy\" title=\"([0-9.]{3,})", string: res1, icase: TRUE );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	if(version == "unknown"){
		vers = eregmatch( pattern: "<div id=\"foot_copy\" title=\"([0-9.]{3,})", string: res2, icase: TRUE );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	set_kb_item( name: "icewarp/mailserver/http/" + port + "/version", value: version );
}
exit( 0 );

