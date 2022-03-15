CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808045" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-3168", "CVE-2016-3163", "CVE-2016-3169" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-05-18 16:17:47 +0530 (Wed, 18 May 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Drupal Multiple Vulnerabilities02- May16 (Linux)" );
	script_tag( name: "summary", value: "This host is running Drupal and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exixts due to:

  - An improper validation of JSON-encoded content in system module.

  - The XML-RPC system allows a large number of calls to the same method.

  - An error in 'user_save' function in User module." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause brute force attacks, to download and execute JSON-encoded
  content and also to gain elevated privileges." );
	script_tag( name: "affected", value: "Drupal 6.x before 6.38 and 7.x before 7.43
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to version 6.38 or 7.43 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2016-001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
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
	if( version_in_range( version: drupalVer, test_version: "6.0", test_version2: "6.37" ) ){
		fix = "6.38";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: drupalVer, test_version: "7.0", test_version2: "7.42" )){
			fix = "7.43";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: drupalVer, fixed_version: fix );
		security_message( data: report, port: drupalPort );
		exit( 0 );
	}
}

