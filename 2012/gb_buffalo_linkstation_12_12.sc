CPE = "cpe:/h:buffalotech:nas";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103617" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "Buffalo Linkstation Privilege Escalation / Information Disclosure" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-12-03 17:27:36 +0100 (Mon, 03 Dec 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_buffalotech_nas_web_detect.sc" );
	script_mandatory_keys( "buffalo/nas/detected" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118532/Buffalo-Linkstation-Privilege-Escalation-Information-Disclosure.html" );
	script_tag( name: "summary", value: "Buffalo Linkstation suffers from information disclosure and privilege escalation vulnerabilities." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = "/modules/webaxs/module/files/password";
if(http_vuln_check( port: port, url: url, pattern: "[a-zA-Z0-9.-_]+:[[a-zA-Z0-9.$/-_]+", check_header: TRUE, extra_check: "text/plain" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

