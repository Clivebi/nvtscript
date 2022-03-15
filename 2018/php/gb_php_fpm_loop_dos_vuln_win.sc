CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812519" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2015-9253" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-19 00:15:00 +0000 (Wed, 19 Feb 2020)" );
	script_tag( name: "creation_date", value: "2018-02-20 17:49:27 +0530 (Tue, 20 Feb 2018)" );
	script_name( "PHP 'PHP-FPM' Denial of Service Vulnerability (Windows)" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=73342" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=70185" );
	script_xref( name: "URL", value: "https://github.com/php/php-src/pull/3287" );
	script_xref( name: "URL", value: "https://www.futureweb.at/security/CVE-2015-9253" );
	script_xref( name: "URL", value: "https://vuldb.com//?id.113566" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the php-fpm master
  process restarts a child process in an endless loop when using program
  execution functions with a non-blocking STDIN stream." );
	script_tag( name: "impact", value: "Successfully exploitation will allow an
  attacker to consume 100% of the CPU, and consume disk space with a large
  volume of error logs, as demonstrated by an attack by a customer of a
  shared-hosting facility." );
	script_tag( name: "affected", value: "PHP versions 5.x up to and including 5.6.36. All 7.0.x versions,
  7.1.x before 7.1.20, 7.2.x before 7.2.8 and 7.3.x before 7.3.0alpha3 on Windows." );
	script_tag( name: "solution", value: "Update to PHP 7.1.20, 7.2.8 or 7.3.0alpha3." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: phpPort, exit_no_version: TRUE )){
	exit( 0 );
}
phpVers = infos["version"];
path = infos["location"];
if( version_in_range( version: phpVers, test_version: "5.0", test_version2: "7.1.19" ) ){
	fix = "7.1.20";
}
else {
	if( IsMatchRegexp( phpVers, "^7\\.2\\." ) && version_is_less( version: phpVers, test_version: "7.2.8" ) ){
		fix = "7.2.8";
	}
	else {
		if(IsMatchRegexp( phpVers, "^7\\.3\\." ) && version_is_less( version: phpVers, test_version: "7.3.0alpha3" )){
			fix = "7.3.0alpha3";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: phpVers, fixed_version: fix, install_path: path );
	security_message( port: phpPort, data: report );
	exit( 0 );
}
exit( 99 );

