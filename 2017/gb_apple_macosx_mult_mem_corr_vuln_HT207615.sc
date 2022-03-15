if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810994" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-2432", "CVE-2017-5029" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-05-19 11:40:15 +0530 (Fri, 19 May 2017)" );
	script_name( "Apple Mac OS X Multiple Memory Corruption Vulnerabilities-HT207615" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple memory corruption vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple memory
  corruption issues due to insufficient input validation and poor memory
  handling." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code and perform an out of bounds memory write." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.12.x through
  10.12.3, 10.11.x through 10.11.6 and 10.10.x through 10.10.5" );
	script_tag( name: "solution", value: "Upgrade Apple Mac OS X 10.12.x to 10.12.4
  or apply the appropriate security patch for Apple Mac OS X 10.11.x and 10.10.x. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207615" );
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
				if(( osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G1421" ) ) || ( osVer == "10.10.5" && version_is_less( version: buildVer, test_version: "14F2315" ) )){
					fix = "Apply patch from vendor";
					osVer = osVer + " Build " + buildVer;
				}
			}
		}
	}
}
else {
	if(version_in_range( version: osVer, test_version: "10.12", test_version2: "10.12.3" )){
		fix = "10.12.4";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

