if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108034" );
	script_version( "2021-01-05T20:30:19+0000" );
	script_tag( name: "last_modification", value: "2021-01-05 20:30:19 +0000 (Tue, 05 Jan 2021)" );
	script_tag( name: "creation_date", value: "2017-01-04 10:00:00 +0100 (Wed, 04 Jan 2017)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Western Digital My Cloud / WD Cloud Products Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Western Digital My Cloud products (Called 'WD Cloud' in Japan)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
url = "/";
port = http_get_port( default: 80 );
res = http_get_cache( item: url, port: port );
if(!res){
	exit( 0 );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 403" )){
	ua = "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0";
	req = http_get_req( port: port, url: url, user_agent: ua, dont_add_xscanner: TRUE );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( IsMatchRegexp( res, "MODEL_ID = \"((WD)?MyCloud[^\"]*|WDCloud)\"" ) || ContainsString( res, "/web/images/logo_WDMyCloud.png" ) )){
	version = "unknown";
	model = "unknown";
	url = "/xml/info.xml";
	req = http_get( item: url, port: port );
	res2 = http_keepalive_send_recv( data: req, port: port, bodyonly: FALSE );
	mo = eregmatch( pattern: "var MODEL_ID = \"((WD)?MyCloud([^\"]*)|WDCloud)\";", string: res );
	if(mo){
		if( mo[1] && mo[1] == "WDCloud" ) {
			model = "WD Cloud";
		}
		else {
			if( mo[3] ) {
				model = mo[3];
			}
			else {
				model = "base";
			}
		}
		concluded = mo[0];
		conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	}
	if(model == "unknown"){
		mo = eregmatch( pattern: "<hw_ver>((WD)?MyCloud([^<]*)|WDCloud)</hw_ver>", string: res2 );
		if(mo){
			if( mo[1] && mo[1] == "WDCloud" ) {
				model = "WD Cloud";
			}
			else {
				if( mo[3] ) {
					model = mo[3];
				}
				else {
					model = "base";
				}
			}
			concluded = mo[0];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
	vers = eregmatch( pattern: "<version>([0-9.]+)</version>", string: res2 );
	if(vers[1]){
		version = vers[1];
		if(concluded){
			concluded += "\n";
		}
		concluded += vers[0];
		if( conclUrl && !ContainsString( conclUrl, url ) ) {
			conclUrl += ", " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			if(!conclUrl){
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
	url = "/nas/v1/locale";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "Content-Type\\s*:\\s*application/json" )){
		admin_user = eregmatch( string: res, pattern: "\\{[^}]*\"admin_username\":\"([^\"]+)\"[^}]*\\}", icase: FALSE );
		if(admin_user[1]){
			set_kb_item( name: "wd-mycloud/http/" + port + "/admin_user", value: admin_user[1] );
			set_kb_item( name: "wd-mycloud/http/" + port + "/extra", value: admin_user[0] );
			set_kb_item( name: "wd-mycloud/http/" + port + "/extraUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		}
	}
	set_kb_item( name: "wd-mycloud/detected", value: TRUE );
	set_kb_item( name: "wd-mycloud/http/detected", value: TRUE );
	set_kb_item( name: "wd-mycloud/http/port", value: port );
	set_kb_item( name: "wd-mycloud/http/" + port + "/version", value: version );
	set_kb_item( name: "wd-mycloud/http/" + port + "/model", value: model );
	if(concluded){
		set_kb_item( name: "wd-mycloud/http/" + port + "/concluded", value: concluded );
	}
	if(conclUrl){
		set_kb_item( name: "wd-mycloud/http/" + port + "/concludedUrl", value: conclUrl );
	}
}
exit( 0 );

