CPE = "cpe:/a:inim:smartlan_g";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143260" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2019-12-17 04:51:38 +0000 (Tue, 17 Dec 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Inim SmartLAN Default Credentials Vulnerability (HTTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_inim_smartlan_consolidation.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "inim/smartlan/http/detected" );
	script_require_ports( "Services/www", 8080, 443 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "SmartLAN is prone to a default account authentication bypass vulnerability
  over HTTP(s)." );
	script_tag( name: "vuldetect", value: "The script tries to login via HTTP(s) with the default credentials." );
	script_tag( name: "solution", value: "Change the password." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
creds = make_array( "admin", "pass", "user", "pass" );
codes = make_list( "9999",
	 "9998",
	 "0001" );
url = dir + "/cgi-bin/web.cgi";
data = "mod=testemail&par=";
for user in keys( creds ) {
	for code in codes {
		headers = make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", "user=" + user + ";pass=" + creds[user] + ";code=" + code );
		req = http_post_put_req( port: port, url: url, data: data, add_headers: headers );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && !ContainsString( res, "no auth" ) && !ContainsString( res, "error" )){
			found += user + "    " + creds[user] + "     " + code + "\n";
		}
	}
}
if(found){
	report = "It was possible to authenticate with the following credentials:\n\n" + "Username Password Code\n" + found;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

