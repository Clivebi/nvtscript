if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813512" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-8897", "CVE-2018-4171" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-06-04 14:09:18 +0530 (Mon, 04 Jun 2018)" );
	script_name( "Apple MacOSX Security Updates(HT208849)-03" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The operating system unable to properly handle an Intel architecture debug
    exception after certain instructions.

  - An information disclosure issue in device properties." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and determine kernel memory layout." );
	script_tag( name: "affected", value: "Apple Mac OS X versions,
  10.11.x through 10.11.6, 10.12.x through 10.12.6." );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.11.6 build
  15G21012 for 10.11.x versions or Apple Mac OS X 10.12 build 16G1408 for 10.12.x
  versions. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208849" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[12]" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[12]" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if(IsMatchRegexp( osVer, "^10\\.11" )){
	if( version_is_less( version: osVer, test_version: "10.11.6" ) ){
		fix = "Upgrade to latest OS(10.11.6) release and apply patch from vendor";
	}
	else {
		if(osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G21012" )){
			fix = "Apply patch from vendor";
			osVer = osVer + " Build " + buildVer;
		}
	}
}
if(IsMatchRegexp( osVer, "^10\\.12" )){
	if( version_is_less( version: osVer, test_version: "10.12.6" ) ){
		fix = "Upgrade to latest OS(10.12.6) release and apply patch from vendor";
	}
	else {
		if(osVer == "10.12.6" && version_is_less( version: buildVer, test_version: "16G1408" )){
			fix = "Apply patch from vendor";
			osVer = osVer + " Build " + buildVer;
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

