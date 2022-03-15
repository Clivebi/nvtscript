CPE = "cpe:/a:vtiger:vtiger_crm";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103290" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-10-06 13:32:57 +0200 (Thu, 06 Oct 2011)" );
	script_cve_id( "CVE-2011-4670" );
	script_bugtraq_id( 49927 );
	script_name( "vtiger CRM Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49927" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Oct/154" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_vtiger_crm_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vtiger/detected" );
	script_tag( name: "summary", value: "vtiger CRM is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "vtiger CRM 5.2.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
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
url = dir + "/phprint.php?module=Home&action=--><script>alert(/vt-xss-test/)</script>&parenttab=MyHomePage\"><script>alert(/vt-xss-test/)</script>&jt=";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/vt-xss-test/\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

