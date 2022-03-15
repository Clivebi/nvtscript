CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809318" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_cve_id( "CVE-2016-7124", "CVE-2016-7125", "CVE-2016-7126", "CVE-2016-7127", "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131", "CVE-2016-7132" );
	script_bugtraq_id( 92756, 92552, 92755, 92757, 92564, 92758 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2016-09-12 18:19:30 +0530 (Mon, 12 Sep 2016)" );
	script_name( "PHP Multiple Vulnerabilities - 02 - Sep16 (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An invalid wddxPacket XML document that is mishandled in a wddx_deserialize
    call in 'ext/wddx/wddx.c' script.

  - An error in 'php_wddx_pop_element' function in 'ext/wddx/wddx.c' script.

  - An error in  'php_wddx_process_data' function in 'ext/wddx/wddx.c' script.

  - Improper handling of the case of a thumbnail offset that exceeds the file
    size in 'exif_process_IFD_in_TIFF' function in 'ext/exif/exif.c' script.

  - Improper validation of gamma values in 'imagegammacorrect' function
    in 'ext/gd/gd.c' script.

  - Improper validation of number of colors in 'imagegammacorrect' function
    in 'ext/gd/gd.c' script.

  - The script 'ext/session/session.c' skips invalid session names in a way that
    triggers incorrect parsing.

  - Improper handling of certain objects in 'ext/standard/var_unserializer.c'
    script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service, to obtain sensitive information
  from process memory, to inject arbitrary-type session data by leveraging control
  of a session name." );
	script_tag( name: "affected", value: "PHP versions prior to 5.6.25 and
  7.x before 7.0.10 on Windows" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.25, or 7.0.10,
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
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
if( version_is_less( version: phpVer, test_version: "5.6.25" ) ){
	fix = "5.6.25";
	VULN = TRUE;
}
else {
	if(IsMatchRegexp( phpVer, "^7\\.0" )){
		if(version_in_range( version: phpVer, test_version: "7.0", test_version2: "7.0.9" )){
			fix = "7.0.10";
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

