if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106162" );
	script_version( "2021-10-05T08:28:55+0000" );
	script_tag( name: "last_modification", value: "2021-10-05 08:28:55 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "creation_date", value: "2016-08-02 08:27:33 +0700 (Tue, 02 Aug 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Progress / Ipswitch WhatsUp Gold Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Progress / Ipswitch WhatsUp Gold." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.whatsupgold.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/NmConsole/";
res = http_get_cache( port: port, item: url );
if( ContainsString( res, "<title>WhatsUp Gold</title>" ) && ContainsString( res, "id=\"microloader\"" ) ){
	version = "unknown";
	concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	url = "/NmConsole/app.js";
	req = http_get( port: port, item: url );
	res = http_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "/NmConsole/api/core/\",version:\"([0-9.]+)", string: res );
	if( !isnull( vers[1] ) ){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	else {
		res = http_get_cache( port: port, item: "/NmConsole/app.json" );
		loc = eregmatch( pattern: "\"path\":\"(app-[0-9.]+js)\"", string: res );
		if(!isnull( loc[1] )){
			url = "/NmConsole/" + loc[1];
			req = http_get( port: port, item: url );
			res = http_send_recv( port: port, data: req );
			vers = eregmatch( pattern: "/NmConsole/api/core/\",version:\"([0-9.]+)", string: res );
			if(!isnull( vers[1] )){
				version = vers[1];
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
}
else {
	host = http_host_name( port: port );
	url = "/NmConsole/CoreNm/User/DlgUserLogin/DlgUserLogin.asp";
	req = "POST " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Accept-Encoding: gzip, deflate\r\n" + "Connection: close\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: 0\r\n\r\n";
	res = http_keepalive_send_recv( port: port, data: req );
	if( ContainsString( res, "Login - WhatsUp Gold" ) ){
		version = "unknown";
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		vers = eregmatch( pattern: "\"VersionText\">.remium Edition&nbsp;v([0-9.]+)( Build ([0-9]+))?", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		if(!isnull( vers[3] )){
			build = vers[3];
			set_kb_item( name: "ipswitch_whatsup/build", value: build );
			extra = "Build:   " + build + "\n";
		}
	}
	else {
		url = "/NmConsole/User/LogIn?AspxAutoDetectCookieSupport=1";
		res = http_get_cache( port: port, item: url );
		if( IsMatchRegexp( res, "Log[ Ii]n - WhatsUp Gold" ) ){
			version = "unknown";
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			exit( 0 );
		}
	}
}
set_kb_item( name: "ipswitch/whatsup_gold/detected", value: TRUE );
set_kb_item( name: "ipswitch/whatsup_gold/http/detected", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:whatsup_gold:" );
if(!cpe){
	cpe = "cpe:/a:ipswitch:whatsup_gold";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Progress / Ipswitch WhatsUp Gold", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
exit( 0 );

