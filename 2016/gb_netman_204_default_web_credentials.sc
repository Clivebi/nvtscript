CPE = "cpe:/a:riello:netman_204";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140003" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "NetMan 204 Default Web Login" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive information that may lead to further attacks." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials" );
	script_tag( name: "solution", value: "Change the password" );
	script_tag( name: "summary", value: "The remote NetMan 204 device has default credentials set." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-28 16:35:07 +0200 (Wed, 28 Sep 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_netman_204_web_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "netman_204/detected" );
	exit( 0 );
}
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
credentials = make_list( "admin",
	 "eurek" );
url = "/cgi-bin/login.cgi";
for credential in credentials {
	data = "username=" + credential + "&password=" + credential;
	req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( buf, "HTTP/1\\.. 200" ) && ContainsString( buf, "session:" ) && ContainsString( buf, "window.location.replace" )){
		co = eregmatch( pattern: "Set-Cookie: (session: [^\r\n]+)", string: buf );
		if(isnull( co[1] )){
			continue;
		}
		cookie = co[1];
		url = "/cgi-bin/changepwd.cgi";
		req = http_get_req( port: port, url: url, add_headers: make_array( "Cookie", cookie ) );
		buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
		if(( ContainsString( buf, ">Change password<" ) && ContainsString( buf, ">Logout<" ) ) || ContainsString( buf, "Another user is logged in. Please retry in a few minutes" )){
			security_message( port: port, data: "It was possible tp login with user `" + credential + "` and password `" + credential + "`" );
			exit( 0 );
		}
	}
}
exit( 99 );

