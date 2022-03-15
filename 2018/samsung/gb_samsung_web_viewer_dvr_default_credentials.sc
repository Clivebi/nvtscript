if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114047" );
	script_version( "2020-11-11T14:11:33+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-11 14:11:33 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-11-12 19:25:24 +0100 (Mon, 12 Nov 2018)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_name( "Samsung Web Viewer DVR Default Credentials" );
	script_dependencies( "gb_samsung_web_viewer_dvr_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "samsung/web_viewer/dvr/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://customvideosecurity.com/blog/tag/default-password-axis/" );
	script_tag( name: "summary", value: "The remote installation of Samsung Web Viewer DVR is using known
  and default credentials for the web interface." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "insight", value: "The installation of Samsung Web Viewer DVR is lacking a proper
  password configuration, which makes critical information and actions accessible to anyone." );
	script_tag( name: "vuldetect", value: "Checks if a successful login to Samsung Web Viewer DVR is possible." );
	script_tag( name: "solution", value: "Change the default credentials." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("string_hex_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("dump.inc.sc");
CPE = "cpe:/a:samsung:web_viewer_dvr";
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "4321", "admin", "111111", "admin", "admin", "root" );
url = "/cgi-bin/webviewer_login_page?loginvalue=0&port=0";
loginUrl = "/cgi-bin/webviewer_cgi_login2";
res = http_get_cache( port: port, item: url );
funcTexts = eregmatch( pattern: "(function [sS]et[Cc]ookie\\(\\)\\{[^\\}]+\\})", string: res );
if(isnull( funcTexts[1] )){
	exit( 99 );
}
funcSetCookie = funcTexts[1];
if( ContainsString( funcSetCookie, "document.login_page_submit.data2.value = do_encrypt(document.login_page.data2.value);" ) ){
	authType = "RSA";
}
else {
	if( ContainsString( funcSetCookie, "document.login_page_submit.data2.value = sha256_digest(document.login_page.data2.value);" ) ){
		authType = "SHA256";
	}
	else {
		if( ContainsString( funcSetCookie, "'&PWD='+encode64(document.login_page.pwd.value)" ) ){
			authType = "Base64";
			loginUrl = "/cgi-bin/webviewer_cgi_login";
		}
		else {
			if( ContainsString( funcSetCookie, "document.login_page_submit.data2.value = hex_func_five(document.login_page.data2.value);" ) ){
				authType = "MD5";
			}
			else {
				exit( 99 );
			}
		}
	}
}
for cred in keys( creds ) {
	username = creds[cred];
	password = cred;
	req = http_get_req( port: port, url: url );
	res = http_send_recv( port: port, data: req );
	funcTexts = eregmatch( pattern: "(function [sS]et[Cc]ookie\\(\\)\\{[^\\}]+\\})", string: res );
	funcSetCookie = funcTexts[1];
	if( ContainsString( funcSetCookie, "document.login_page_submit.data3.value = val_rand;" ) ){
		data3Num = "0." + rand_str( charset: "0123456789", length: 16 );
	}
	else {
		if( ( randNum = eregmatch( pattern: "document.login_page_submit.data3.value\\s*=\\s*([0-9.]+);", string: funcSetCookie ) ) && authType != "RSA" ){
			data3Num = randNum[1];
		}
		else {
			if( ContainsString( funcSetCookie, "document.login_page_submit.data3.value" ) ){
				data3Num = "0." + rand_str( charset: "0123456789", length: 16 );
			}
			else {
				data3Num = "0." + rand_str( charset: "0123456789", length: 16 );
			}
		}
	}
	if(authType == "RSA"){
		if( ContainsString( funcSetCookie, "document.login_page_submit.data4.value = val_rand;" ) ){
			data4Num = "0." + rand_str( charset: "0123456789", length: 16 );
		}
		else {
			if( randNum = eregmatch( pattern: "document.login_page_submit.data4.value\\s*=\\s*([0-9.]+);", string: funcSetCookie ) ){
				data4Num = randNum[1];
			}
			else {
				if( ContainsString( funcSetCookie, "document.login_page_submit.data4.value" ) ){
					data4Num = "0." + rand_str( charset: "0123456789", length: 16 );
				}
				else {
					data4Num = "0." + rand_str( charset: "0123456789", length: 16 );
				}
			}
		}
	}
	if( authType == "RSA" ){
		if(!defined_func( "rsa_public_encrypt" )){
			exit( 0 );
		}
		url = "/cgi-bin/webviewer_login_page?lang=en&loginvalue=3&port=0&data3=" + data3Num;
		req = http_get_req( port: port, url: url, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ) );
		res = http_keepalive_send_recv( port: port, data: req );
		modu = eregmatch( pattern: "var rsa_modulus='([0-9a-fA-F]+)';", string: res );
		if(isnull( modu[1] )){
			continue;
		}
		if(strlen( modu[1] ) % 2){
			modu[1] = "0" + modu[1];
		}
		rsa_modulus = hex2raw( s: modu[1] );
		exp = eregmatch( pattern: "var rsa_exponent='([0-9]+)';", string: res );
		if(isnull( exp[1] )){
			continue;
		}
		if(strlen( exp[1] ) % 2){
			exp[1] = "0" + exp[1];
		}
		rsa_exponent = hex2raw( s: exp[1] );
		rem_addr = eregmatch( pattern: "<input type=hidden name=remote_addr\\s*value=([0-9.]+)>", string: res );
		if(isnull( rem_addr[1] )){
			continue;
		}
		remote_address = rem_addr[1];
		pass = hexstr( rsa_public_encrypt( data: password, e: rsa_exponent, n: rsa_modulus, pad: "TRUE" ) );
		data = "lang=en&port=0&close_user_session=0&data1=" + base64( str: username ) + "%3D&data2=" + pass + "&data3=" + data3Num + "&data4=" + data4Num + "&remote_addr=" + remote_address;
		req = http_post_put_req( port: port, url: loginUrl, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Cache-Control", "max-age=0", "Upgrade-Insecure-Requests", "1", "Content-Type", "application/x-www-form-urlencoded", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ) );
		res = http_send_recv( port: port, data: req );
	}
	else {
		if( authType == "SHA256" ){
			rem_addr = eregmatch( pattern: "<input type=hidden name=remote_addr\\s*value=([0-9.]+)>", string: res );
			if(isnull( rem_addr[1] )){
				continue;
			}
			remote_address = rem_addr[1];
			data = "lang=en&port=0&close_user_session=0&data1=" + base64( str: username ) + "%3D&data2=" + hexstr( SHA256( password ) ) + "&data3=" + data3Num + "&data4=" + data3Num + "&remote_addr=" + remote_address;
			req = http_post_put_req( port: port, url: loginUrl, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Cache-Control", "max-age=0", "Upgrade-Insecure-Requests", "1", "Content-Type", "application/x-www-form-urlencoded", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ) );
			res = http_send_recv( port: port, data: req );
		}
		else {
			if( authType == "Base64" ){
				data = "close_user_session=0&lang=en&port=0&id=" + username + "&pwd=" + password;
				auth = "ID=" + base64( str: username ) + "=&PWD=" + base64( str: password ) + "==&SessionID=" + data3Num;
				req = http_post_put_req( port: port, url: loginUrl, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Cache-Control", "max-age=0", "Upgrade-Insecure-Requests", "1", "Content-Type", "application/x-www-form-urlencoded", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Cookie", auth ) );
				res = http_send_recv( port: port, data: req );
			}
			else {
				if(authType == "MD5"){
					data = "lang=en&port=0&close_user_session=0&data1=" + base64( str: username ) + "%3D&data2=" + hexstr( MD5( password ) );
					auth = "DATA1=" + base64( str: username ) + "&DATA2=" + base64( str: password ) + "&SDATA3=" + data3Num;
					req = http_post_put_req( port: port, url: loginUrl, data: data, add_headers: make_array( "Accept-Encoding", "gzip, deflate", "Cache-Control", "max-age=0", "Upgrade-Insecure-Requests", "1", "Content-Type", "application/x-www-form-urlencoded", "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Cookie", auth ) );
					res = http_send_recv( port: port, data: req );
				}
			}
		}
	}
	if(IsMatchRegexp( res, "top.document.location.href='../index.htm\\?port=[0-9]+';" ) && !IsMatchRegexp( res, "<\\s*body\\s*onload\\s*=\\s*'movetoauth\\(\\)'\\s*>" )){
		VULN = TRUE;
		report += "\nusername: \"" + username + "\", password: \"" + password + "\"";
	}
}
if(VULN){
	report = "It was possible to login with the following default credentials: " + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

