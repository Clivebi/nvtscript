CPE = "cpe:/o:avm:fritz%21_os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108042" );
	script_version( "2020-04-15T09:02:26+0000" );
	script_tag( name: "last_modification", value: "2020-04-15 09:02:26 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-01-10 15:00:00 +0100 (Tue, 10 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "AVM FRITZ!Box Default / no Password (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_avm_fritz_box_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "avm_fritz_box/http/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "This script detects if the device has:

  - a default password set

  - no password set" );
	script_tag( name: "vuldetect", value: "Check if the device is not password protected or if it is
  possible to login with a default password." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "solution", value: "Set a password or change the identified default password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
func create_response( challenge, credential ){
	var challenge, response, str, credential;
	str = challenge + "-" + credential;
	response = challenge + "-" + hexstr( MD5( ascii2unicode( data: str ) ) );
	return response;
}
func do_webcm_post_req( port, posturl, sid, dir ){
	var port, posturl, sid, dir, time, postdata, req, res;
	time = unixtime();
	if( sid ){
		postdata = "sid=" + sid + "&getpage=..%2Fhtml%2Flogincheck.html&errorpage=..%2Fhtml%2Findex.html" + "&var%3Alang=de&var%3Apagename=home&var%3Amenu=home&var%3Amenutitle=Home" + "&time%3Asettings%2Ftime=" + time + "%2C-60";
	}
	else {
		postdata = "getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html&var%3Alang=de" + "&var%3Apagename=home&var%3Amenu=home&time%3Asettings%2Ftime=" + time + "%2C-60";
	}
	req = http_post_put_req( port: port, url: posturl, data: postdata, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests", "1", "Referer", http_report_vuln_url( port: port, url: dir + "/cgi-bin/webcm?getpage=../html/index_inhalt.html", url_only: TRUE ) ) );
	res = http_send_recv( port: port, data: req );
	return res;
}
credentials = make_list( "1234",
	 "0000",
	 "admin",
	 "password",
	 "passwort" );
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/cgi-bin/webcm?getpage=../html/index_inhalt.html";
req = http_get( port: port, item: url );
res = http_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<form method=\"POST\" action=\"../cgi-bin/webcm\"" ) || ContainsString( res, "<form method=\"GET\" action=\"../cgi-bin/webcm\"" ) )){
	posturl = dir + "/cgi-bin/webcm";
	sid = eregmatch( pattern: "sid\" value=\"([a-z0-9]+)\" id=\"uiPostSid", string: res );
	if( !isnull( sid[1] ) ){
		res = do_webcm_post_req( port: port, posturl: posturl, sid: sid[1], dir: dir );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<label for=\"uiViewUsePassword\">" ) && ContainsString( res, "<label for=\"uiViewPasswordConfirm\">" ) && ContainsString( res, "<label for=\"uiShowReminder\">" )){
			report = "The URL " + http_report_vuln_url( port: port, url: "/", url_only: TRUE ) + " has no password set.";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	else {
		res = do_webcm_post_req( port: port, posturl: posturl, dir: dir );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<p class=\"ac\">FRITZ!Box" ) && ContainsString( res, "Firmware-Version" )){
			report = "The URL " + http_report_vuln_url( port: port, url: "/", url_only: TRUE ) + " has no password set.";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	sleepsecs = 1;
	for credential in credentials {
		url = dir + "/cgi-bin/webcm?getpage=../html/index_inhalt.html";
		req = http_get( port: port, item: url );
		res = http_send_recv( port: port, data: req );
		sid = eregmatch( pattern: "sid\" value=\"([a-z0-9]+)\" id=\"uiPostSid", string: res );
		if( !isnull( sid[1] ) ){
			res = do_webcm_post_req( port: port, posturl: posturl, sid: sid[1], dir: dir );
			challenge = eregmatch( pattern: "var challenge = \"([a-z0-9]+)\";", string: res );
			if(!isnull( challenge[1] )){
				response = create_response( challenge: challenge[1], credential: credential );
				postdata = "sid=0000000000000000&getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html" + "&var%3Alang=de&var%3Apagename=home&var%3Amenu=home&login%3Acommand%2Fresponse=" + response;
				req = http_post_put_req( port: port, url: posturl, data: postdata, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests", "1", "Referer", http_report_vuln_url( port: port, url: dir + "/cgi-bin/webcm", url_only: TRUE ) ) );
				res = http_send_recv( port: port, data: req );
				if(IsMatchRegexp( res, "HTTP/1\\.. 200" ) && ( ContainsString( res, "<img src=\"../html/de/images/Logout.gif\"></a>" ) || ContainsString( res, "value=\"../html/confirm_logout.html\">" ) )){
					report = "It was possible to login at " + http_report_vuln_url( port: port, url: "/", url_only: TRUE ) + " with the password '" + credential + "'.";
					security_message( port: port, data: report );
					exit( 0 );
				}
			}
			sleepsecs *= 2;
			sleep( sleepsecs );
		}
		else {
			postdata = "getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html&var%3Alang=de&var%3Apagename=home" + "&var%3Amenu=home&login%3Acommand%2Fpassword=" + credential;
			req = http_post_put_req( port: port, url: "/cgi-bin/webcm", data: postdata, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests", "1", "Referer", http_report_vuln_url( port: port, url: dir + "/cgi-bin/webcm", url_only: TRUE ) ) );
			res = http_send_recv( port: port, data: req );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<p class=\"ac\">FRITZ!Box" ) && ContainsString( res, "Firmware-Version" )){
				report = "It was possible to login at " + http_report_vuln_url( port: port, url: "/", url_only: TRUE ) + " with the password '" + credential + "'.";
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
url = dir + "/home/home.lua";
req = http_get( port: port, item: url );
res = http_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "HTTP/1\\.. 200" ) && ( ContainsString( res, "<img src=\"/css/default/images/icon_abmelden.gif\">" ) || ContainsString( res, "<li><a href=\"/net/network_user_devices.lua?sid=" ) || ContainsString( res, "<li><a href=\"/system/syslog.lua?sid=" ) )){
	report = "The URL " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " has no password set.";
	security_message( port: port, data: report );
	exit( 0 );
}
url = dir + "/login.lua";
req = http_get( port: port, item: url );
res = http_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "method=\"POST\" action=\"/login.lua\"" ) || ContainsString( res, "method=\"post\" action=\"/login.lua\"" ) )){
	url = dir + "/logincheck.lua";
	req = http_get( port: port, item: url );
	res = http_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 303" ) && ContainsString( res, "/no_password.lua?sid=" )){
		sid = eregmatch( pattern: "/no_password\\.lua\\?sid=([a-z0-9]+)", string: res );
		if(!isnull( sid[1] )){
			url = "/home/home.lua?sid=" + sid[1];
			req = http_get( port: port, item: url );
			res = http_send_recv( port: port, data: req );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<img src=\"/css/default/images/icon_abmelden.gif\">" ) || ContainsString( res, "<li><a href=\"/net/network_user_devices.lua?sid=" ) || ContainsString( res, "<li><a href=\"/system/syslog.lua?sid=" ) )){
				report = "The URL " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " has no password set.";
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
	url = dir + "/login.lua";
	for credential in credentials {
		fbsleepsecs = 2;
		req = http_get( port: port, item: url );
		res = http_send_recv( port: port, data: req );
		challenge = eregmatch( pattern: "<br>security:status/challenge = ([a-z0-9]+)", string: res );
		if( isnull( challenge[1] ) ){
			challenge = eregmatch( pattern: "g_challenge = \"([a-z0-9]+)\"", string: res );
			if(isnull( challenge[1] )){
				continue;
			}
		}
		else {
			isOld = TRUE;
		}
		response = create_response( challenge: challenge[1], credential: credential );
		if( isOld ){
			postdata = "response=" + response;
		}
		else {
			postdata = "response=" + response + "&page=%2Fhome%2Fhome.lua&username=";
		}
		req = http_post_put_req( port: port, url: url, data: postdata, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests", "1", "Referer", http_report_vuln_url( port: port, url: url, url_only: TRUE ) ) );
		res = http_send_recv( port: port, data: req );
		if( IsMatchRegexp( res, "^HTTP/1\\.[01] 303" ) && ContainsString( res, "/home/home.lua?sid=" ) ){
			sid = eregmatch( pattern: "/home/home\\.lua\\?sid=([a-z0-9]+)", string: res );
			if(isnull( sid[1] )){
				continue;
			}
			url = "/home/home.lua?sid=" + sid[1];
			req = http_get( port: port, item: url );
			res = http_send_recv( port: port, data: req );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<img src=\"/css/default/images/icon_abmelden.gif\">" ) || ContainsString( res, "<li><a href=\"/net/network_user_devices.lua?sid=" ) || ContainsString( res, "<li><a href=\"/system/syslog.lua?sid=" ) )){
				report = "It was possible to login at " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " with the password '" + credential + "'.";
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
		else {
			sleepsecs = eregmatch( pattern: "<br>security:status/login_blocked = ([0-9]+)", string: res );
			if( !isnull( sleepsecs[1] ) ){
				sleepsecs = sleepsecs[1];
			}
			else {
				fbsleepsecs *= 2;
				sleepsecs = fbsleepsecs;
			}
			sleep( sleepsecs );
		}
	}
}
url = dir + "/";
req = http_get( port: port, item: url );
res = http_send_recv( port: port, data: req );
if( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"lua\":" ) && ( ContainsString( res, "\"internet\\/dsl_test.lua\"" ) || ContainsString( res, "\"assis\\/assi_fax_intern.lua\"" ) || ContainsString( res, "\"dect\\/podcast.lua\"" ) || ContainsString( res, "\"wlan\\/wlan_settings.lua\"" ) ) ){
	report = "The URL " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " has no password set.";
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "FRITZ!Box" ) && ContainsString( res, "login.init(data);" )){
		fbsleepsecs = 2;
		for credential in credentials {
			req = http_get( port: port, item: url );
			res = http_send_recv( port: port, data: req );
			challenge = eregmatch( pattern: "\"challenge\": ?\"([a-z0-9]+)\",", string: res );
			if(isnull( challenge[1] )){
				continue;
			}
			response = create_response( challenge: challenge[1], credential: credential );
			postdata = "response=" + response + "&lp=&username=";
			req = http_post_put_req( port: port, url: url, data: postdata, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests", "1", "Referer", http_report_vuln_url( port: port, url: url, url_only: TRUE ) ) );
			res = http_send_recv( port: port, data: req );
			if( IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"lua\":" ) && ( ContainsString( res, "\"internet\\/dsl_test.lua\"" ) || ContainsString( res, "\"assis\\/assi_fax_intern.lua\"" ) || ContainsString( res, "\"dect\\/podcast.lua\"" ) || ContainsString( res, "\"wlan\\/wlan_settings.lua\"" ) ) ){
				report = "It was possible to login at " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " with the password '" + credential + "'.";
				security_message( port: port, data: report );
				exit( 0 );
			}
			else {
				sleepsecs = eregmatch( pattern: "\"blockTime\": ?([0-9]+),", string: res );
				if( !isnull( sleepsecs[1] ) ){
					sleepsecs = sleepsecs[1];
				}
				else {
					fbsleepsecs *= 2;
					sleepsecs = fbsleepsecs;
				}
				sleep( sleepsecs );
			}
		}
	}
}
exit( 99 );

