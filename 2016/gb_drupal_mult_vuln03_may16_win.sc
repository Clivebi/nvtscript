CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808046" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-3170", "CVE-2016-3162" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-05-18 16:19:48 +0530 (Wed, 18 May 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Multiple Vulnerabilities03- May16 (Windows)" );
	script_tag( name: "summary", value: "This host is running Drupal and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exixts due to:

  - An email address can be matched to an account.

  - An improper validation of File module." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause information disclosure, bypass access restrictions and
  read, delete, or substitute a link to a file." );
	script_tag( name: "affected", value: "Drupal 7.x before 7.43 and 8.x before
  8.0.4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 7.43 or 8.0.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2016-001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( drupalVer, "^(7|8)" )){
	if( version_in_range( version: drupalVer, test_version: "7.0", test_version2: "7.42" ) ){
		fix = "7.43";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: drupalVer, test_version: "8.0.0", test_version2: "8.0.3" )){
			fix = "8.0.4";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: drupalVer, fixed_version: fix );
		security_message( data: report, port: drupalPort );
		exit( 0 );
	}
}

