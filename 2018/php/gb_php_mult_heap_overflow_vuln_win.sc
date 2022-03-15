CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813597" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-14851", "CVE-2018-14883", "CVE-2018-15132" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-06 12:58:19 +0530 (Mon, 06 Aug 2018)" );
	script_name( "PHP Multiple Heap Buffer Overflow and Information Disclosure Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "PHP is prone to multiple heap buffer overflow and information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - exif_process_IFD_in_MAKERNOTE function in exif.c file suffers from
  improper validation against crafted JPEG files.

  - exif_thumbnail_extract function in exif.c file suffers from improper
  validation of length of 'ImageInfo->Thumbnail.offset + ImageInfo->Thumbnail.size'

  - linkinfo function on windows doesn't implement openbasedir check." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause heap overflow, denial of service and disclose sensitive information." );
	script_tag( name: "affected", value: "PHP versions before 5.6.37, 7.0.x before
  7.0.31, 7.1.x before 7.1.20, and 7.2.x before 7.2.8." );
	script_tag( name: "solution", value: "Update to PHP version 5.6.37, 7.0.31,
  7.1.20 or 7.2.8 or later. Please see the references for more information." );
	script_xref( name: "URL", value: "https://access.redhat.com/security/cve/cve-2018-14851" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=76557" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=76423" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=76459" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(!infos = get_app_version_and_location( cpe: CPE, port: phpPort, exit_no_version: TRUE )){
	exit( 0 );
}
phpVers = infos["version"];
path = infos["location"];
if( version_is_less( version: phpVers, test_version: "5.6.37" ) ){
	fix = "5.6.37";
}
else {
	if( version_in_range( version: phpVers, test_version: "7.0", test_version2: "7.0.30" ) ){
		fix = "7.0.31";
	}
	else {
		if( version_in_range( version: phpVers, test_version: "7.1", test_version2: "7.1.19" ) ){
			fix = "7.1.20";
		}
		else {
			if(version_in_range( version: phpVers, test_version: "7.2", test_version2: "7.2.7" )){
				fix = "7.2.8";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: phpVers, fixed_version: fix, install_path: path );
	security_message( port: phpPort, data: report );
	exit( 0 );
}

