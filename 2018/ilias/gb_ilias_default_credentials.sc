if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107313" );
	script_version( "2020-11-27T13:21:49+0000" );
	script_tag( name: "last_modification", value: "2020-11-27 13:21:49 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-05-29 14:54:24 +0200 (Tue, 29 May 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "ILIAS Default Credentials (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_ilias_detect.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "ilias/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "ILIAS is using default administrative credentials." );
	script_tag( name: "vuldetect", value: "The script tries to log in using the default credentials." );
	script_tag( name: "insight", value: "ILIAS has a default administrative account called 'root' with the password 'homer'." );
	script_tag( name: "impact", value: "If unchanged, an attacker can use the default credentials to log in and gain administrative privileges." );
	script_tag( name: "affected", value: "All ILIAS versions." );
	script_tag( name: "solution", value: "Change the 'root' account's password." );
	script_xref( name: "URL", value: "https://www.ilias.de/docu/goto_docu_pg_6488_367.html" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
CPE = "cpe:/a:ilias:ilias";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
func check_v53( port, dir ){
	var port, dir, req, res, clientid, phpsessionid, data, add_headers, report;
	req = http_get( port: port, item: dir + "/" );
	res = http_keepalive_send_recv( port: port, data: req );
	clientid = http_get_cookie_from_header( buf: res, pattern: "ilClientId=([^; ]+)" );
	if(isnull( clientid )){
		return;
	}
	phpsessionid = http_get_cookie_from_header( buf: res, pattern: "PHPSESSID=([^; ]+)" );
	if(isnull( phpsessionid )){
		return;
	}
	data = NASLString( "username=root&password=homer&cmd%5BdoStandardAuthentication%5D=Login" );
	add_headers = make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid, "Content-Type", "application/x-www-form-urlencoded" );
	req = http_post_put_req( port: port, url: dir + "/ilias.php?lang=en&client_id=" + clientid + "&cmd=post&cmdClass=ilstartupgui&cmdNode=wr&baseClass=ilStartUpGUI&rtoken=", data: data, add_headers: add_headers );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && location = http_extract_location_from_redirect( port: port, data: res, current_dir: dir )){
		phpsessionid = http_get_cookie_from_header( buf: res, pattern: "PHPSESSID=([^; ]+)" );
		if(isnull( phpsessionid )){
			return;
		}
		req = http_get_req( port: port, url: location, add_headers: make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid ) );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && location = http_extract_location_from_redirect( port: port, data: res, current_dir: dir )){
			req = http_get_req( port: port, url: location, add_headers: make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid ) );
			res = http_keepalive_send_recv( port: port, data: req );
		}
	}
	if(ContainsString( res, "You have to change your initial password before you can start using ILIAS services." )){
		security_message( port: port, data: "It was possible to log in to the Web Interface using the default user 'root' with the default password 'homer'." );
		exit( 0 );
	}
	return;
}
func check_v50( port, dir ){
	var port, dir, req, res, clientid, sessionid, phpsessionid, authchallenge, data, add_headers, report;
	req = http_get( port: port, item: dir + "/" );
	res = http_keepalive_send_recv( port: port, data: req );
	sessionid = http_get_cookie_from_header( buf: res, pattern: "SESSID=([^; ]+)" );
	if(isnull( sessionid )){
		return;
	}
	clientid = http_get_cookie_from_header( buf: res, pattern: "ilClientId=([^; ]+)" );
	if(isnull( clientid )){
		return;
	}
	phpsessionid = http_get_cookie_from_header( buf: res, pattern: "PHPSESSID=([^; ]+)" );
	if(isnull( phpsessionid )){
		return;
	}
	data = NASLString( "username=root&password=homer&cmd%5BshowLogin%5D=Login" );
	add_headers = make_array( "Cookie", "SESSID=" + sessionid + ";" + "ilClientId=" + clientid + ";" + "iltest=cookie" + ";" + "PHPSESSID=" + phpsessionid + ";" + "authchallenge=" + authchallenge + ";", "Content-Type", "application/x-www-form-urlencoded" );
	req = http_post_put_req( port: port, url: dir + "/ilias.php?lang=en&client_id=" + clientid + "&cmd=post&cmdClass=ilstartupgui&cmdNode=30&baseClass=ilStartUpGUI&rtoken=", data: data, add_headers: add_headers );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && location = http_extract_location_from_redirect( port: port, data: res, current_dir: dir )){
		phpsessionid = http_get_cookie_from_header( buf: res, pattern: "PHPSESSID=([^; ]+)" );
		if(isnull( phpsessionid )){
			return;
		}
		authchallenge = http_get_cookie_from_header( buf: res, pattern: "authchallenge=([^; ]+)" );
		if(isnull( authchallenge )){
			return;
		}
		req = http_get_req( port: port, url: location, add_headers: make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid + ";" + "authchallenge=" + authchallenge ) );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && location = http_extract_location_from_redirect( port: port, data: res, current_dir: dir )){
			req = http_get_req( port: port, url: location, add_headers: make_array( "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid + ";" + "authchallenge=" + authchallenge ) );
			res = http_keepalive_send_recv( port: port, data: req );
		}
	}
	if(ContainsString( res, "Welcome to your Personal Desktop!" )){
		security_message( port: port, data: "It was possible to log in to the Web Interface using the default user 'root' with the default password 'homer'." );
		exit( 0 );
	}
	return;
}
func check_v44( port, dir ){
	var port, dir, req, res, clientid, phpsessionid, authchallenge, data, add_headers, report;
	req = http_get( port: port, item: dir + "/" );
	res = http_keepalive_send_recv( port: port, data: req );
	clientid = http_get_cookie_from_header( buf: res, pattern: "ilClientId=([^; ]+)" );
	if(isnull( clientid )){
		return;
	}
	phpsessionid = http_get_cookie_from_header( buf: res, pattern: "PHPSESSID=([^; ]+)" );
	if(isnull( phpsessionid )){
		return;
	}
	data = NASLString( "username=root&password=homer&cmd%5BshowLogin%5D=Login" );
	add_headers = make_array( "Cookie", "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid + ";" + "iltest=cookie", "Content-Type", "application/x-www-form-urlencoded" );
	req = http_post_put_req( port: port, url: dir + "/ilias.php?lang=en&client_id=" + clientid + "&cmd=post&cmdClass=ilstartupgui&cmdNode=nm&baseClass=ilStartUpGUI&rtoken=", data: data, add_headers: add_headers );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && location = http_extract_location_from_redirect( port: port, data: res, current_dir: dir )){
		phpsessionid = http_get_cookie_from_header( buf: res, pattern: "PHPSESSID=([^; ]+)" );
		if(isnull( phpsessionid )){
			return;
		}
		authchallenge = http_get_cookie_from_header( buf: res, pattern: "authchallenge=([^; ]+)" );
		if(isnull( authchallenge )){
			return;
		}
		req = http_get_req( port: port, url: location, add_headers: make_array( "Cookie", "iltest=cookie" + ";" + "ilClientId=" + clientid + ";" + "PHPSESSID=" + phpsessionid + ";" + "authchallenge=" + authchallenge ) );
		res = http_keepalive_send_recv( port: port, data: req );
	}
	if(ContainsString( res, "<h1>Welcome to your Personal Desktop!</h1>" )){
		security_message( port: port, data: "It was possible to log in to the Web Interface using the default user 'root' with the default password 'homer'." );
		exit( 0 );
	}
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
check_v53( port: port, dir: dir );
check_v50( port: port, dir: dir );
check_v44( port: port, dir: dir );
exit( 99 );

