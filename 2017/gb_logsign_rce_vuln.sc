CPE = "cpe:/a:logsign:logsign";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106651" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-03-14 12:58:36 +0700 (Tue, 14 Mar 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Logsign Remote Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_logsign_detect.sc" );
	script_mandatory_keys( "logsign/installed" );
	script_tag( name: "summary", value: "Logsign is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP request and checks the response." );
	script_tag( name: "insight", value: "Logsign has a publicly accessible endpoint. That endpoint takes a user input
and then use it during operating system command execution without proper validation." );
	script_tag( name: "solution", value: "Logsign provides a patch to solve this vulnerability." );
	script_xref( name: "URL", value: "https://pentest.blog/unexpected-journey-3-visiting-another-siem-and-uncovering-pre-auth-privileged-remote-code-execution/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
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
url = dir + "/api/log_browser/validate";
rand = rand_str( length: 15, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz" );
data = "{\"file\":\"" + rand + ".raw\"}";
req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/json" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "{\"message\": \"success\", \"success\": true}" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

