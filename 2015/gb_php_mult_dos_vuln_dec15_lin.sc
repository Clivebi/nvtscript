CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806649" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-7804", "CVE-2015-7803" );
	script_bugtraq_id( 76959 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-12-15 17:44:53 +0530 (Tue, 15 Dec 2015)" );
	script_name( "PHP Multiple Denial of Service Vulnerabilities - 01 - Dec15 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple denial of service (DoS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An Off-by-one error in the 'phar_parse_zipfile' function within ext/phar/zip.c
    script.

  - An error in the 'phar_get_entry_data' function in ext/phar/util.c script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service (NULL pointer dereference and
  application crash)." );
	script_tag( name: "affected", value: "PHP versions before 5.5.30 and 5.6.x
  before 5.6.14" );
	script_tag( name: "solution", value: "Update to PHP 5.5.30 or 5.6.14 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=70433" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/10/05/8" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
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
if( IsMatchRegexp( phpVer, "^5\\.6" ) ){
	if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.13" )){
		fix = "5.6.14";
		VULN = TRUE;
	}
}
else {
	if(version_is_less( version: phpVer, test_version: "5.5.30" )){
		fix = "5.5.30";
		VULN = TRUE;
	}
}
if(VULN){
	report = "Installed Version: " + phpVer + "\n" + "Fixed Version:     " + fix + "\n";
	security_message( data: report, port: phpPort );
	exit( 0 );
}
exit( 99 );

