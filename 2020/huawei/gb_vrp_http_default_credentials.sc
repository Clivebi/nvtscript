if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108746" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-04-15 08:04:09 +0000 (Wed, 15 Apr 2020)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Huawei VRP Default Credentials (HTTP)" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "huawei/vrp/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1000178166/1257fc63/what-is-the-default-login-password" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1000060368/25506195/understanding-the-list-of-default-user-names-and-passwords" );
	script_tag( name: "summary", value: "The remote Huawei Versatile Routing Platform (VRP) device is using
  known default credentials for the Web-Login." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The remote Huawei Versatile Routing Platform (VRP) device is lacking
  a proper password configuration, which makes critical information and actions accessible for people
  with knowledge of the default credentials." );
	script_tag( name: "vuldetect", value: "Tries to login using the default credentials: 'admin:admin',
  'root:admin', 'admin:admin@huawei.com' or 'super:sp-admin'." );
	script_tag( name: "solution", value: "Change the default password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("dump.inc.sc");
CPE_PREFIX = "cpe:/o:huawei:";
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/" );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 301" )){
	exit( 0 );
}
if( ContainsString( res, "/simple/view/login.html" ) ) {
	type = 0;
}
else {
	if( ContainsString( res, "/view/loginPro.html" ) ) {
		type = 1;
	}
	else {
		if( ContainsString( res, "/view/login.html" ) ) {
			type = 2;
		}
		else {
			type = 3;
		}
	}
}
creds = make_list( "admin:admin@huawei.com",
	 "admin:admin",
	 "root:admin",
	 "super:sp-admin" );
url = "/login.cgi";
headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
for cred in creds {
	split = split( buffer: cred, sep: ":", keep: FALSE );
	if(max_index( split ) != 2){
		continue;
	}
	username = split[0];
	password = split[1];
	valid_login = FALSE;
	if( type == 0 ) {
		post_data_list = make_list( "UserName=" + username + "&Password=" + password + "&Edition=0" );
	}
	else {
		if( type == 1 || type == 2 ) {
			post_data_list = make_list( "UserName=" + username + "&Password=" + password + "&LanguageType=0" );
		}
		else {
			post_data_list = make_list( "UserName=" + username + "&Password=" + password + "&LanguageType=0",
				 "UserName=" + username + "&Password=" + password + "&Edition=0" );
		}
	}
	for post_data in post_data_list {
		req = http_post_put_req( port: port, url: url, data: post_data, add_headers: headers );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res){
			continue;
		}
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 403" )){
			exit( 0 );
		}
		if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) || ContainsString( res, "ErrorMsg=1008" )){
			continue;
		}
		sessionid = http_get_cookie_from_header( buf: res, pattern: "(SessionID=[^;]+;)" );
		if(!sessionid){
			continue;
		}
		body = http_extract_body_from_response( data: res );
		if(!body){
			continue;
		}
		valid_login = TRUE;
		break;
	}
	if(!valid_login){
		continue;
	}
	location = eregmatch( string: body, pattern: "Location=([^&]+)", icase: FALSE );
	if( !location[1] && ( ContainsString( body, "ChangeFlag=2" ) || ContainsString( body, "ChangeFlag=1" ) ) ){
		if( type == 0 ) {
			urls = make_list( "/simple/view/main/modifyPwd.html" );
		}
		else {
			if( type == 1 ) {
				urls = make_list( "/professional/view/main/modifyPwd.html" );
			}
			else {
				if( type == 2 ) {
					urls = make_list( "/view/main/modifyPwd.html" );
				}
				else {
					urls = make_list( "/simple/view/main/modifyPwd.html",
						 "/professional/view/main/modifyPwd.html",
						 "/view/main/modifyPwd.html" );
				}
			}
		}
	}
	else {
		if( !location[1] ){
			if( type == 0 ) {
				urls = make_list( "/simple/view/main/main.html" );
			}
			else {
				if( type == 1 ) {
					urls = make_list( "/professional/view/main/default.html" );
				}
				else {
					if( type == 2 ) {
						urls = make_list( "/view/main/default.html" );
					}
					else {
						urls = make_list( "/simple/view/main/main.html",
							 "/professional/view/main/default.html",
							 "/view/main/default.html" );
					}
				}
			}
		}
		else {
			urls = make_list( location[1] );
		}
	}
	token = eregmatch( string: body, pattern: "Token=([^&]+)", icase: FALSE );
	if( type == 0 ){
		cookie = "LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=" + username + "; loginFlag=true; " + sessionid;
		if(token[1]){
			cookie += " Token=" + token[1];
		}
		cookies = make_list( cookie );
	}
	else {
		if( type == 1 ) {
			cookies = make_list( "loginUrl=loginPro; FactoryName=Huawei%20Technologies%20Co.; FactoryLogoUrl=../../images/; Package=NO; " + sessionid + " ResetFlag=0; loginFlag=true; ARlanguage=property-en_CN.js" );
		}
		else {
			if( type == 2 ) {
				cookies = make_list( "resetFlag=0; language=property-en_CN.js; " + sessionid + " userName=" + username );
			}
			else {
				cookies = make_list( "LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=" + username + "; loginFlag=true; " + sessionid + " " + token[1],
					 "loginUrl=loginPro; FactoryName=Huawei%20Technologies%20Co.; FactoryLogoUrl=../../images/; Package=NO; " + sessionid + " ResetFlag=0; loginFlag=true; ARlanguage=property-en_CN.js",
					 "resetFlag=0; language=property-en_CN.js; " + sessionid + " userName=" + username );
			}
		}
	}
	for cookie in cookies {
		headers = make_array( "Cookie", cookie );
		valid_creds = FALSE;
		for url in urls {
			url = url + "?language=en";
			if(type == 2){
				url += "&pageid=" + rand_str( length: 5, charset: "0123456789" );
			}
			req = http_get_req( port: port, url: url, add_headers: headers );
			res = http_keepalive_send_recv( port: port, data: req );
			if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
				continue;
			}
			if( ContainsString( res, "icbs_lang=\"LG.publicModule.equ_board\"" ) || ContainsString( res, "icbs_lang=\"LG.tree.common_maintenance\"" ) || ContainsString( res, "Current User: " + username ) || ContainsString( res, "<span id=\"current_login_userName\"" ) || ContainsString( res, "onclick=\"confirmLogout" ) || ContainsString( res, "icbs_lang=LG.publicModule.languageBtn" ) ){
				VULN = TRUE;
				valid_creds = TRUE;
				report += "\nUsername: \"" + username + "\", Password: \"" + password + "\", URL: \"" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\"";
				break;
			}
			else {
				if(ContainsString( res, "'loginCaption' id='oldPasswordCaption'" ) || ContainsString( res, "'loginCaption' id='newPasswordCaption'" )){
					VULN = TRUE;
					valid_creds = TRUE;
					report += "\nUsername: \"" + username + "\", Password: \"" + password + "\" (The system is enforcing a change of the current password), URL: \"" + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\"";
					break;
				}
			}
		}
		if(valid_creds){
			if( type == 0 ){
				headers = make_array( "Referer", http_report_vuln_url( port: port, url: url, url_only: TRUE ), "Content-Type", "application/x-www-form-urlencoded; text/xml; charset=UTF-8", "Token", token[1], "Cookie", "LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=" + username + "; " + sessionid );
				message_id = rand_str( length: 3, charset: "0123456789" );
				post_data = "MessageID=" + message_id + "&<rpc message-id=\"" + message_id + "\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n<close-session/></rpc>]]>]]>";
				req = http_post_put_req( port: port, url: "/config.cgi", data: post_data, add_headers: headers );
				http_keepalive_send_recv( port: port, data: req );
			}
			else {
				if( type == 1 ){
					req = http_get_req( port: port, url: "/professional/view/deviceSummary/equSummary.html", add_headers: headers );
					res = http_keepalive_send_recv( port: port, data: req );
					token = eregmatch( string: res, pattern: "tTag = \"([^\"]+)\";", icase: FALSE );
					headers = make_array( "Referer", http_report_vuln_url( port: port, url: url, url_only: TRUE ), "Content-Type", "application/x-www-form-urlencoded; text/xml; charset=UTF-8", "Token", token[1], "Cookie", cookie );
					message_id = rand_str( length: 3, charset: "0123456789" );
					post_data = "htmlID=1001&MessageID=" + message_id + "&<rpc message-id=\"" + message_id + "\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n<close-session/></rpc>]]>]]>";
					req = http_post_put_req( port: port, url: "/professional/view/main/config.cgi", data: post_data, add_headers: headers );
					http_keepalive_send_recv( port: port, data: req );
				}
				else {
					if(type == 2){
						token = eregmatch( string: res, pattern: "tTag = \"([^\"]+)\";", icase: FALSE );
						headers = make_array( "Referer", http_report_vuln_url( port: port, url: url, url_only: TRUE ), "Content-Type", "application/x-www-form-urlencoded; text/xml; charset=UTF-8", "Token", token[1], "Cookie", cookie );
						message_id = rand_str( length: 3, charset: "0123456789" );
						post_data = "htmlID=1000&MessageID=" + message_id + "&<rpc message-id=\"" + message_id + "\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n<close-session/></rpc>]]>]]>";
						req = http_post_put_req( port: port, url: "/config.cgi", data: post_data, add_headers: headers );
						http_keepalive_send_recv( port: port, data: req );
					}
				}
			}
			break;
		}
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials:\n" + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

