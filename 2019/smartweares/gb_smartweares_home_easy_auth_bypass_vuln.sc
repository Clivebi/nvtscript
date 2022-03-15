CPE = "cpe:/a:smartweares:home_easy";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143111" );
	script_version( "2020-11-16T10:23:42+0000" );
	script_tag( name: "last_modification", value: "2020-11-16 10:23:42 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-11-12 02:34:08 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Smartweares HOME easy Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_smartwares_home_easy_http_detect.sc" );
	script_mandatory_keys( "smartweares/home_easy/detected" );
	script_tag( name: "summary", value: "Smartweares HOME easy is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "HOME easy suffers from information disclosure and client-side authentication
  bypass vulnerability through IDOR by navigating to several administrative web pages. This allowed disclosing an
  SQLite3 database file and location. Other functionalities are also accessible by disabling JavaScript in your
  browser, bypassing the client-side validation and redirection." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5540.php" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/web-en/system.html";
if(http_vuln_check( port: port, url: url, pattern: "Network Settings", check_header: TRUE, extra_check: "Change Password" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

