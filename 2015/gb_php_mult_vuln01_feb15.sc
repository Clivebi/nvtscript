CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805446" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0232", "CVE-2015-0231", "CVE-2014-9652", "CVE-2014-9653" );
	script_bugtraq_id( 72505, 72516, 72541, 72539 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-02-06 11:43:37 +0530 (Fri, 06 Feb 2015)" );
	script_name( "PHP Multiple Vulnerabilities - 01 - Feb15" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Flaw in the 'exif_process_unicode' function in ext/exif/exif.c script when
  parsing JPEG EXIF entries.

  - A use-after-free error in the 'process_nested_data' function in
  ext/standard/var_unserializer.re script.

  - a flaw in 'readelf.c' script in Fine Free File.

  - an out-of-bounds read flaw in 'src/softmagic.c' script in Fine Free File." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service or possibly execute arbitrary code
  via different crafted dimensions." );
	script_tag( name: "affected", value: "PHP versions 5.4.x before 5.4.37, 5.5.x
  before 5.5.21, and 5.6.x before 5.6.5" );
	script_tag( name: "solution", value: "Update to PHP version 5.4.37 or 5.5.21
  or 5.6.5 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=68799" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=68710" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
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
if(IsMatchRegexp( phpVer, "^5\\.[4-6]" )){
	if(version_in_range( version: phpVer, test_version: "5.4.0", test_version2: "5.4.36" )){
		fix = "5.4.37";
		VULN = TRUE;
	}
	if(version_in_range( version: phpVer, test_version: "5.5.0", test_version2: "5.5.20" )){
		fix = "5.5.21";
		VULN = TRUE;
	}
	if(version_in_range( version: phpVer, test_version: "5.6.0", test_version2: "5.6.4" )){
		fix = "5.6.5";
		VULN = TRUE;
	}
	if(VULN){
		report = report_fixed_ver( installed_version: phpVer, fixed_version: fix );
		security_message( data: report, port: phpPort );
		exit( 0 );
	}
}
exit( 99 );

