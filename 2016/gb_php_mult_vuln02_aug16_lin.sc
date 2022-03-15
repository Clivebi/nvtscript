CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808790" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-5771", "CVE-2016-5770" );
	script_bugtraq_id( 91401, 91403 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2016-08-17 12:32:47 +0530 (Wed, 17 Aug 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 02 - Aug16 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The 'spl_array.c' in the SPL extension improperly interacts with the
    unserialize implementation and garbage collection.

  - The integer overflow in the 'SplFileObject::fread' function in
    'spl_directory.c' in the SPL extension." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (use-after-free and application
  crash) or possibly execute arbitrary code or possibly have unspecified other
  impact via a large integer argument." );
	script_tag( name: "affected", value: "PHP versions prior to 5.5.37 and 5.6.x
  before 5.6.23 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.37, or 5.6.23,
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!phpVer = get_app_version( cpe: CPE, port: phpPort )){
	exit( 0 );
}
if( version_is_less( version: phpVer, test_version: "5.5.37" ) ){
	fix = "5.5.37";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( phpVer, "^5\\.6" )){
		if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.22" )){
			fix = "5.6.23";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: phpVer, fixed_version: fix );
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

