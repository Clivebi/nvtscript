CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813162" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2018-10545" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-05-03 10:25:53 +0530 (Thu, 03 May 2018)" );
	script_name( "PHP Security Bypass Vulnerability May18 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the dumpable FPM child
  processes allow bypassing opcache access controls" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass security restrictions and access sensitive configuration data for
  other accounts directly in the PHP worker process's memory." );
	script_tag( name: "affected", value: "PHP versions prior to 5.6.35,

  PHP versions 7.2.x prior to 7.2.4,

  PHP versions 7.0.x prior to 7.0.29,

  PHP versions 7.1.x prior to 7.1.16 on Linux." );
	script_tag( name: "solution", value: "Update to version 7.2.4 or 7.0.29 or
  5.6.35 or 7.1.16 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php#5.6.35" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php#7.0.29" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php#7.1.16" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php#7.2.4" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phport = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: phport, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( version_in_range( version: vers, test_version: "7.2", test_version2: "7.2.3" ) ){
	fix = "7.2.4";
}
else {
	if( version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.28" ) ){
		fix = "7.0.29";
	}
	else {
		if( version_in_range( version: vers, test_version: "7.1", test_version2: "7.1.15" ) ){
			fix = "7.1.16";
		}
		else {
			if(version_is_less( version: vers, test_version: "5.6.35" )){
				fix = "5.6.35";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: phport, data: report );
	exit( 0 );
}
exit( 0 );

