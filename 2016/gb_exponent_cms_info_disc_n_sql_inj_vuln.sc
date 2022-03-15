CPE = "cpe:/a:exponentcms:exponent_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809728" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-9284", "CVE-2016-9285", "CVE-2016-9282", "CVE-2016-9283", "CVE-2016-9242", "CVE-2016-9183", "CVE-2016-9184", "CVE-2016-9182", "CVE-2016-9481" );
	script_bugtraq_id( 94296, 94194, 94227, 94227, 94590 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-11-17 13:31:19 +0530 (Thu, 17 Nov 2016)" );
	script_name( "Exponent CMS Information Disclosure and SQL Injection Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_exponet_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ExponentCMS/installed" );
	script_xref( name: "URL", value: "https://github.com/exponentcms/exponent-cms/releases" );
	script_xref( name: "URL", value: "https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.0patch1" );
	script_xref( name: "URL", value: "https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.0patch2" );
	script_tag( name: "summary", value: "This host is installed with Exponent CMS
  and is prone to sql injection and information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check if response is disclosing sensitive user information." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in 'getUsersByJSON' in
  framework/modules/users/controllers/usersController.php script.

  - An error in framework/modules/addressbook/controllers/addressController.php
  script while passing input via modified id number.

  - An input passed via 'search_string' parameter to
  framework/modules/search/controllers/searchController.php script is not validated
  properly.

  - An error in framework/core/subsystems/expRouter.php script allowing to read
  database information via address/addContentToSearch/id/ and a trailing string.

  - Input passed via 'content_type' and 'subtype' parameter to
  framework/modules/core/controllers/expRatingController.php script is not validated
  properly.

  - Insufficient sanitization of input passed via 'selectObjectsBySql' to
  /framework/modules/ecommerce/controllers/orderController.php script.

  - Insufficient validation of input passed to
  /framework/modules/core/controllers/expHTMLEditorController.php script.

  - Exponent CMS permits undefined actions to execute by default.

  - Input passed via 'content_id' parameter into showComments within
  framework/modules/core/controllers/expCommentController.php script is not
  sanitized properly." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and execute
  arbitrary SQL commands." );
	script_tag( name: "affected", value: "Exponent CMS version 2.4.0." );
	script_tag( name: "solution", value: "Update to the latest release version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
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
url = dir + "/users/getUsersByJSON/sort/" + vtstrings["default"] + "test";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "admin\",\"password\":\"[a-zA-Z0-9]", extra_check: make_list( "content=\"Exponent Content Management System",
	 "lastname",
	 "firstname",
	 "email",
	 "recordsReturned" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

