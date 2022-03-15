if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812401" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-13868", "CVE-2017-13869", "CVE-2017-3735", "CVE-2017-13855", "CVE-2017-13844", "CVE-2017-9798", "CVE-2017-13847", "CVE-2017-13833", "CVE-2017-10002", "CVE-2017-13867", "CVE-2017-13862", "CVE-2017-7172", "CVE-2017-1000254", "CVE-2017-15422", "CVE-2017-7159", "CVE-2017-7162", "CVE-2017-13904", "CVE-2017-7173", "CVE-2017-7154" );
	script_bugtraq_id( 100515, 100872, 101946 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-28 16:38:00 +0000 (Thu, 28 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-12-07 10:51:36 +0530 (Thu, 07 Dec 2017)" );
	script_name( "Apple MacOSX Security Updates(HT208331)-02" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Security update includes,

  - A validation issue was addressed with improved input sanitization.

  - An out-of-bounds read issue existed in X.509 IPAddressFamily parsing.

  - A type confusion issue was addressed with improved memory handling.

  - A memory corruption issue was addressed with improved memory handling.

  - Multiple issues were addressed by updating to version 2.4.28.

  - Multiple memory corruption issues were addressed through improved state management.

  - An out-of-bounds read was addressed with improved bounds checking.

  - An out-of-bounds read issue existed in the FTP PWD response parsing.

  - An integer overflow error.

  - An input validation issue existed in the kernel." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read restricted memory, execute arbitrary code with system
  privileges." );
	script_tag( name: "affected", value: "Apple Mac OS X versions,
  10.13.x through 10.13.1, 10.12.x through 10.12.6, 10.11.x through 10.11.6" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208331" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[1-3]" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[1-3]" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if(IsMatchRegexp( osVer, "^10\\.11" )){
	if( version_in_range( version: osVer, test_version: "10.11", test_version2: "10.11.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.11.6"){
			if(osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G18013" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
if( IsMatchRegexp( osVer, "^10\\.12" ) ){
	if( version_in_range( version: osVer, test_version: "10.12", test_version2: "10.12.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.12.6"){
			if(osVer == "10.12.6" && version_is_less( version: buildVer, test_version: "16G1114" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
else {
	if(osVer == "10.13.1"){
		fix = "10.13.2";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

