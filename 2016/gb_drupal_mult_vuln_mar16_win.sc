CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807480" );
	script_version( "2019-05-16T08:02:32+0000" );
	script_cve_id( "CVE-2016-3164" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "creation_date", value: "2016-03-15 09:57:38 +0530 (Tue, 15 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Multiple Vulnerabilities - March16 (Windows)" );
	script_tag( name: "summary", value: "This host is running Drupal and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the current path being populated with
  an external URL." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to conduct open redirect attack." );
	script_tag( name: "affected", value: "Drupal 6.x before 6.38, 7.x before 7.43
  and 8.X before 8.0.4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 6.38 or 7.43 or
  8.0.4 later." );
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
if(IsMatchRegexp( drupalVer, "^(6|7|8)" )){
	if( version_in_range( version: drupalVer, test_version: "6.0", test_version2: "6.37" ) ){
		fix = "6.38";
		VULN = TRUE;
	}
	else {
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
	}
	if(VULN){
		report = report_fixed_ver( installed_version: drupalVer, fixed_version: fix );
		security_message( data: report, port: drupalPort );
		exit( 0 );
	}
}

