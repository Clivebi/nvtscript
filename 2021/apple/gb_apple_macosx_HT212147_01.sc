if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817903" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-1761", "CVE-2021-1776", "CVE-2021-1772", "CVE-2021-1792", "CVE-2021-1787", "CVE-2021-1786", "CVE-2021-1766", "CVE-2021-1782", "CVE-2021-1750", "CVE-2020-29633", "CVE-2021-1771", "CVE-2021-1763", "CVE-2021-1767", "CVE-2021-1745", "CVE-2021-1753", "CVE-2021-1768", "CVE-2021-1751", "CVE-2020-25709" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-09 12:31:00 +0000 (Fri, 09 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-02-03 17:23:29 +0530 (Wed, 03 Feb 2021)" );
	script_name( "Apple MacOSX Security Updates(HT212147)-01" );
	script_tag( name: "summary", value: "Apple Mac OS X is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple input validation errors.

  - An improper state management, bounds checking in multiple components." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause arbitrary code execution and denial of service." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 11.x through 11.0.1,
  10.14.x prior to Security Update 2021-001 Mojave, 10.15.x prior to 10.15.7
  Security Update 2021-001 Catalina." );
	script_tag( name: "solution", value: "Apply Security Update 2021-001 for 10.14.x,
  Security Update 2021-001 for 10.15.x or upgrade to Apple Mac OS X 11.2 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212147" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || ( !IsMatchRegexp( osVer, "^10\\.1[45]\\." ) && !IsMatchRegexp( osVer, "^11\\." ) ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if(IsMatchRegexp( osVer, "^10\\.15" )){
	if( version_in_range( version: osVer, test_version: "10.15", test_version2: "10.15.6" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.15.7"){
			if(version_is_less( version: buildVer, test_version: "19H512" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
if( IsMatchRegexp( osVer, "^10\\.14" ) ){
	if( version_in_range( version: osVer, test_version: "10.14", test_version2: "10.14.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.14.6"){
			if(version_is_less( version: buildVer, test_version: "18G8012" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
else {
	if(version_in_range( version: osVer, test_version: "11.0", test_version2: "11.0.1" )){
		fix = "11.2";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

