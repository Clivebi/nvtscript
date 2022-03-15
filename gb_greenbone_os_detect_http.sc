if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112137" );
	script_version( "2020-10-08T08:12:30+0000" );
	script_tag( name: "last_modification", value: "2020-10-08 08:12:30 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "creation_date", value: "2017-11-23 10:50:05 +0100 (Thu, 23 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the Greenbone Security Manager (GSM) /
  Greenbone OS (GOS)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/login/login.html";
buf = http_get_cache( item: url, port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ( ContainsString( buf, "<title>Greenbone Security Assistant" ) && ContainsString( buf, "Greenbone OS" ) ) || ContainsString( buf, "\"title\">Greenbone Security Manager</span>" ) || ContainsString( buf, "<title>Greenbone Security Manager</title>" ) )){
	set_kb_item( name: "greenbone/gos/detected", value: TRUE );
	set_kb_item( name: "greenbone/gos/http/detected", value: TRUE );
	set_kb_item( name: "greenbone/gos/http/port", value: port );
	set_kb_item( name: "greenbone/gos/http/" + port + "/detected", value: TRUE );
	replace_kb_item( name: "www/" + port + "/can_host_php", value: "no" );
	replace_kb_item( name: "www/" + port + "/can_host_asp", value: "no" );
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "<(div|span) class=\"(gos_)?version\">(Version )?Greenbone OS ([^<]+)</(div|span)>", icase: FALSE );
	if(!isnull( version[4] )){
		vers = version[4];
		concluded = version[0];
		conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	if(vers == "unknown"){
		url2 = "/config.js";
		req = http_get( item: url2, port: port );
		buf2 = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( buf2, "^HTTP/1\\.[01] 200" ) && ContainsString( buf2, "Greenbone OS" )){
			version = eregmatch( string: buf2, pattern: "vendorVersion: 'Greenbone OS ([^']+)',", icase: FALSE );
			if(!isnull( version[1] )){
				vers = version[1];
				concluded = version[0];
				conclurl = http_report_vuln_url( port: port, url: "/login", url_only: TRUE );
			}
		}
	}
	type = "unknown";
	_type = eregmatch( string: buf, pattern: "<img src=\"/img/gsm-([^>]+)_label\\.svg\"></img>", icase: FALSE );
	if(!_type[1]){
		_type = eregmatch( string: buf, pattern: "<img src=\"/img/GSM_([^>]+)_logo_95x130\\.png\" alt=\"\"></td>", icase: FALSE );
	}
	if(!_type[1]){
		_type = eregmatch( string: buf2, pattern: "vendorLabel: 'gsm-([^']+)_label\\.svg',", icase: FALSE );
		if(_type[1]){
			conclurl += " and " + http_report_vuln_url( port: port, url: url2, url_only: TRUE );
		}
	}
	if(_type[1]){
		type = toupper( _type[1] );
		concluded += "\n" + _type[0];
	}
	set_kb_item( name: "greenbone/gos/http/" + port + "/version", value: vers );
	set_kb_item( name: "greenbone/gsm/http/" + port + "/type", value: type );
	if(concluded){
		set_kb_item( name: "greenbone/gos/http/" + port + "/concluded", value: concluded );
		set_kb_item( name: "greenbone/gos/http/" + port + "/concludedUrl", value: conclurl );
	}
}
exit( 0 );

