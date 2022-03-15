CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807885" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_cve_id( "CVE-2016-6211" );
	script_bugtraq_id( 91230 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:31:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2016-09-26 15:08:08 +0530 (Mon, 26 Sep 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Drupal 'User' Module Privilege Escalation Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is running Drupal and is prone
  to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw exists due to error within the 'User'
  module, where a specific code can trigger a rebuild of the user profile form
  and a registered user can be granted all user roles on the site." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to administrative privileges." );
	script_tag( name: "affected", value: "Drupal core 7.x versions prior to 7.44" );
	script_tag( name: "solution", value: "Upgrade to version 7.44 or newer." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2016-002" );
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
if(version_in_range( version: drupalVer, test_version: "7.0", test_version2: "7.43" )){
	report = report_fixed_ver( installed_version: drupalVer, fixed_version: "7.44" );
	security_message( data: report, port: drupalPort );
	exit( 0 );
}

