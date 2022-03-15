CPE = "cpe:/a:teampass:teampass";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108025" );
	script_version( "2020-04-15T09:02:26+0000" );
	script_tag( name: "last_modification", value: "2020-04-15 09:02:26 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-12-13 10:00:00 +0100 (Tue, 13 Dec 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "TeamPass Default Admin Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_teampass_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "teampass/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "This script detects default admin credentials for TeamPass." );
	script_tag( name: "vuldetect", value: "Check if it is possible to login with default admin credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "insight", value: "It was possible to login with default credentials 'admin:admin'." );
	script_tag( name: "solution", value: "Change the password of the 'admin' account." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
for posturl in make_list( "/sources/main.queries.php",
	 "/sources/identify.php" ) {
	url = dir + "/index.php";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	cookie = eregmatch( pattern: "Set-Cookie: (PHPSESSID=[A-Za-z0-9;]+)", string: res );
	if(!isnull( cookie[1] )){
		cookie = cookie[1];
	}
	keycookie = eregmatch( pattern: "(KEY_PHPSESSID=[A-Za-z0-9;%]+)", string: res );
	if(!isnull( keycookie[1] )){
		cookie += " " + keycookie[1];
	}
	if(isnull( cookie )){
		continue;
	}
	csrfcookie = eregmatch( pattern: "Set-Cookie: ([a-z0-9]+=[a-z0-9;]+)", string: res );
	if(!isnull( csrfcookie[1] )){
		cookie += " " + csrfcookie[1];
	}
	encrypted = eregmatch( pattern: "id=\"encryptClientServer\" value=\"([01]+)\"", string: res );
	if(encrypted[1] == "1"){
		continue;
	}
	randomstring = rand_str( length: 10, charset: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz" );
	logindata = "{\"login\":\"admin\" , \"pw\":\"admin\" , \"duree_session\":\"1\" , \"screenHeight\":\"1080\" , \"randomstring\":\"" + randomstring + "\"}";
	postdata = "type=identify_user&data=" + logindata;
	if(!isnull( csrfcookie[1] )){
		postdata += "&" + csrfcookie[1] - ";";
	}
	posturl = dir + posturl;
	req = http_post_put_req( port: port, url: posturl, data: postdata, accept_header: "application/json, text/javascript, */*; q=0.01", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", cookie ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( res, "Hacking attempt..." ) && IsMatchRegexp( res, "HTTP/1\\.. 200" ) && ContainsString( res, "user_admin" ) && ContainsString( res, randomstring )){
		report = "It was possible to login to the URL " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " with the default credentials 'admin:admin'.";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

