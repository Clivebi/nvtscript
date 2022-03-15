CPE = "cpe:/a:concrete5:concrete5";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106762" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-19 09:03:26 +0200 (Wed, 19 Apr 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 20:42:00 +0000 (Thu, 15 Jul 2021)" );
	script_cve_id( "CVE-2017-7725", "CVE-2017-8082" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Concrete5 Header Injection and CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_mandatory_keys( "concrete5/installed" );
	script_tag( name: "summary", value: "Concrete5 CMS is prone to a header injection and CSRF vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist because:

  - Concrete5 places incorrect trust in the HTTP Host header during caching, if
the administrator did not define a 'canonical' URL on installation of Concrete5 using the 'Advanced Options'
settings. Remote attackers can make a GET request with any domain name in the Host header. This is stored and
allows for arbitrary domains to be set for certain links displayed to subsequent visitors, potentially an XSS
vector.

  - Concrete5's Thumbnail Editor in the File Manager is vulnerable to CSRF, which allows remote attackers to disable the entire
installation of Concrete5, by merely tricking an admin view a malicious page. This results in a site-wide denial of service
meaning neither the admin OR any of the website users can access the site." );
	script_tag( name: "affected", value: "Concrete5 version 8.x." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://hyp3rlinx.altervista.org/advisories/CONCRETE5-v8.1.0-HOST-HEADER-INJECTION.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

