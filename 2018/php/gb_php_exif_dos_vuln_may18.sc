CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813625" );
	script_version( "2021-09-07T08:17:19+0000" );
	script_cve_id( "CVE-2018-12882" );
	script_bugtraq_id( 104551 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 08:17:19 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 11:46:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-06-28 14:52:09 +0530 (Thu, 28 Jun 2018)" );
	script_name( "PHP 'ext/exif/exif.c' DoS Vulnerability" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the 'exif_read_from_impl'
  function of the 'ext/exif/exif.c' script ." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to cause
  a DoS condition, denying service to legitimate users." );
	script_tag( name: "affected", value: "PHP versions 7.2.0 through 7.2.7." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=76409" );
	script_xref( name: "URL", value: "https://bugs.php.net/patch-display.php?bug=76409&patch=avoid-double-free.patch&revision=1528027735" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
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
if(version_in_range( version: vers, test_version: "7.2.0", test_version2: "7.2.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: phport, data: report );
	exit( 0 );
}
exit( 99 );

