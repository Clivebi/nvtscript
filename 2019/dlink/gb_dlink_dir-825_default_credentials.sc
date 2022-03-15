if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113342" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-26 11:30:00 +0100 (Tue, 26 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_cve_id( "CVE-2019-9123" );
	script_name( "D-Link DIR-825 Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/is_dlink_dir_device", "d-link/dir/model" );
	script_tag( name: "summary", value: "D-Link DIR-825 devices use an empty default password
  for the accounts 'admin' and 'user'." );
	script_tag( name: "vuldetect", value: "Tries to login with an empty password." );
	script_tag( name: "solution", value: "Set a password for the accounts 'admin' and 'user'." );
	script_xref( name: "URL", value: "https://github.com/WhooAmii/whooamii.github.io/blob/master/2018/DIR-825/Permission%20access%20control.md" );
	exit( 0 );
}
CPE = "cpe:/h:d-link:dir-825";
require("host_details.inc.sc");
require("misc_func.inc.sc");
;
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!location = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(location == "/"){
	location = "";
}
url = location + "/cgi-bin/webproc";
for user in make_list( "Admin",
	 "User" ) {
	buf = http_get_cache( item: url, port: port );
	sys_token = eregmatch( string: buf, pattern: "var G_SysToken[ ]*=[ ]*\"([0-9]+)\";", icase: TRUE );
	if(isnull( sys_token[1] )){
		exit( 0 );
	}
	session_id = eregmatch( string: buf, pattern: "set-cookie: sessionid=([^;]+);", icase: TRUE );
	if(isnull( session_id[1] )){
		exit( 0 );
	}
	xxid = eregmatch( string: buf, pattern: "set-cookie: xxid=([0-9]+);", icase: TRUE );
	if(isnull( xxid[1] )){
		exit( 0 );
	}
	headers = make_array( "Cookie", "sessionid=" + session_id[1] + "; auth=nok; xxid=" + xxid[1] + "; sys_UserName=" + user );
	post_data = NASLString( "getpage=html%2Findex.html;", "errorpage=html%2Fmain.html;", "var%3Amenu=basic;", "obj-action=auth;", "%3Ausername=" + user + ";", "%3Apassword=;", "var%3Asys_Token=" + sys_token[1] + ";", "%3Aaction=login;", "%3Asessionid=" + session_id[1] + ";" );
	req = http_post_put_req( port: port, url: url, data: post_data, add_headers: headers, accept_header: "*/*", host_header_use_ip: TRUE );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "set-cookie[ ]?:[ ]?auth[ ]?=[ ]?ok" )){
		report = "It was possible to login as user '" + user + "' without a password.";
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

