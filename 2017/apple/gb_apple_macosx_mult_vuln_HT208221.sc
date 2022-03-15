if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811959" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-13801", "CVE-2017-13804", "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13080" );
	script_bugtraq_id( 100249, 101274 );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-11-02 12:40:42 +0530 (Thu, 02 Nov 2017)" );
	script_name( "Apple MacOSX Multiple Vulnerabilities HT208221" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A logic issue existed in the handling of state transitions.

  - A path handling issue.

  - A validation issue existed which allowed local file access.

  - An out-of-bounds read." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code with system privileges and disclose sensitive information." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.13, 10.12.x
  through 10.12.6, 10.11.x through 10.11.6" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X version
  10.13.1 or apply the appropriate patch." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208221" );
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
if( IsMatchRegexp( osVer, "^10\\.1[12]" ) ){
	if( version_in_range( version: osVer, test_version: "10.11", test_version2: "10.11.5" ) || version_in_range( version: osVer, test_version: "10.12", test_version2: "10.12.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.11.6" || osVer == "10.12.6"){
			buildVer = get_kb_item( "ssh/login/osx_build" );
			if(buildVer){
				if(( osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G17023" ) ) || ( osVer == "10.12.6" && version_is_less( version: buildVer, test_version: "16G1036" ) )){
					fix = "Apply patch from vendor";
					osVer = osVer + " Build " + buildVer;
				}
			}
		}
	}
}
else {
	if(osVer == "10.13"){
		fix = "10.13.1";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

