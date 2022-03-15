if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810984" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_cve_id( "CVE-2017-2527", "CVE-2017-6990", "CVE-2017-6979", "CVE-2017-2516", "CVE-2017-2546", "CVE-2017-2512", "CVE-2017-2535", "CVE-2017-2524", "CVE-2017-2537", "CVE-2017-2541", "CVE-2017-2548", "CVE-2017-2540" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-16 15:41:39 +0530 (Tue, 16 May 2017)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-01-HT207797" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple validation issues due to improper input sanitization.

  - Multiple memory corruption issues due to poor memory handling.

  - A resource exhaustion issue due to improper input sanitization." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to obtain sensitive information, gain extra privileges, execute arbitrary code,
  and bypass security restrictions." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.11.x through
  10.11.6, 10.10.x through 10.10.5 and 10.12.x through 10.12.4" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207797" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[0-2]" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[0-2]" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if( IsMatchRegexp( osVer, "^10\\.1[01]" ) ){
	if( version_in_range( version: osVer, test_version: "10.11", test_version2: "10.11.5" ) || version_in_range( version: osVer, test_version: "10.10", test_version2: "10.10.4" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.11.6" || osVer == "10.10.5"){
			buildVer = get_kb_item( "ssh/login/osx_build" );
			if(buildVer){
				if(( osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G1510" ) ) || ( osVer == "10.10.5" && version_is_less_equal( version: buildVer, test_version: "14F2315" ) )){
					fix = "Apply patch from vendor";
					osVer = osVer + " Build " + buildVer;
				}
			}
		}
	}
}
else {
	if(version_in_range( version: osVer, test_version: "10.12", test_version2: "10.12.4" )){
		fix = "10.12.5";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

