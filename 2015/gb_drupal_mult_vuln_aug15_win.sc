CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806103" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-6661", "CVE-2015-6660", "CVE-2015-6658" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-28 11:55:16 +0530 (Fri, 28 Aug 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Multiple Vulnerabilities - August15 (Windows)" );
	script_tag( name: "summary", value: "This host is running Drupal and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exixts as,

  - The Form API in the application does not properly validate the form token.

  - There is no restriction to get node titles by reading the menu.

  - Insufficient sanitization of user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to sensitive information, execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site and
  conduct CSRF attacks." );
	script_tag( name: "affected", value: "Drupal 6.x before 6.37 and 7.x before 7.39
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 6.37 or 7.39
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2015-003" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!drupalPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!drupalVer = get_app_version( cpe: CPE, port: drupalPort, version_regex: "^[0-9]\\.[0-9]+" )){
	exit( 0 );
}
if(IsMatchRegexp( drupalVer, "^(6|7)" )){
	if(version_in_range( version: drupalVer, test_version: "6.0", test_version2: "6.36" )){
		fix = "6.37";
		VULN = TRUE;
	}
	if(version_in_range( version: drupalVer, test_version: "7.0", test_version2: "7.38" )){
		fix = "7.39";
		VULN = TRUE;
	}
	if(VULN){
		report = "Installed version: " + drupalVer + "\n" + "Fixed version:     " + fix + "\n";
		security_message( data: report, port: drupalPort );
		exit( 0 );
	}
}

