CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813160" );
	script_version( "2021-06-02T11:05:57+0000" );
	script_cve_id( "CVE-2018-10549", "CVE-2018-10546", "CVE-2018-10548", "CVE-2018-10547" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-05-02 18:02:28 +0530 (Wed, 02 May 2018)" );
	script_name( "PHP Multiple Vulnerabilities May18 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - An out of bounds read error in 'exif_read_data' function while processing
    crafted JPG data.

  - An error in stream filter 'convert.iconv' which leads to infinite loop on
    invalid sequence.

  - An error in the LDAP module of PHP which allows a malicious LDAP server or
    man-in-the-middle attacker to crash PHP.

  - An error in the 'phar_do_404()' function in 'ext/phar/phar_object.c' script
    which returns parts of the request unfiltered, leading to another XSS vector.
    This is due to incomplete fix for CVE-2018-5712." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct XSS attacks, crash PHP, conduct denial-of-service condition and
  execute arbitrary code in the context of the affected application." );
	script_tag( name: "affected", value: "PHP versions prior to 5.6.36,

  PHP versions 7.2.x prior to 7.2.5,

  PHP versions 7.0.x prior to 7.0.30,

  PHP versions 7.1.x prior to 7.1.17 on Linux." );
	script_tag( name: "solution", value: "Update to version 7.2.5 or 7.0.30 or
  5.6.36 or 7.1.17 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php#5.6.36" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php#7.0.30" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php#7.1.17" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php#7.2.5" );
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
if( version_in_range( version: vers, test_version: "7.2", test_version2: "7.2.4" ) ){
	fix = "7.2.5";
}
else {
	if( version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.29" ) ){
		fix = "7.0.30";
	}
	else {
		if( version_in_range( version: vers, test_version: "7.1", test_version2: "7.1.16" ) ){
			fix = "7.1.17";
		}
		else {
			if(version_is_less( version: vers, test_version: "5.6.36" )){
				fix = "5.6.36";
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

