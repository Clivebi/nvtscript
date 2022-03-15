CPE = "cpe:/a:drupal:drupal";
if(description){
	script_xref( name: "URL", value: "http://drupal.org/node/318706" );
	script_oid( "1.3.6.1.4.1.25623.1.0.800123" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-11-04 15:12:12 +0100 (Tue, 04 Nov 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-4789", "CVE-2008-4790", "CVE-2008-4791", "CVE-2008-4793" );
	script_name( "Drupal Core Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc" );
	script_mandatory_keys( "drupal/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "This host is installed with Drupal and is prone to
  multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation allows authenticated users to bypass
  access restrictions and can even allows unauthorized users to obtain sensitive information." );
	script_tag( name: "insight", value: "Flaws are due to:

  - logic error in the core upload module validation, which allows unprivileged users to attach files.

  - ability to view attached file content which they don't have access.

  - deficiency in the user module allows users who had been blocked by access rules.

  - weakness in the node module API allows for node validation to be bypassed in certain circumstances." );
	script_tag( name: "affected", value: "Drupal Version 5.x prior to 5.11 and 6.x prior to 6.5 on all running platform." );
	script_tag( name: "solution", value: "Upgrade Drupal Version 5.x to 5.11/6.x to Drupal 6.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!drupalVer = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if( IsMatchRegexp( drupalVer, "^6\\.[0-4]" ) && version_is_less( version: drupalVer, test_version: "6.5" ) ){
	report = report_fixed_ver( installed_version: drupalVer, fixed_version: "6.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(IsMatchRegexp( drupalVer, "^5.[0-9]" ) && version_is_less( version: drupalVer, test_version: "5.11" )){
		report = report_fixed_ver( installed_version: drupalVer, fixed_version: "5.11" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

