if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812663" );
	script_version( "2021-05-31T06:00:14+0200" );
	script_cve_id( "CVE-2018-4098", "CVE-2018-4082", "CVE-2018-4085", "CVE-2018-4084" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:14 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-27 17:22:00 +0000 (Fri, 27 Apr 2018)" );
	script_tag( name: "creation_date", value: "2018-01-24 11:37:13 +0530 (Wed, 24 Jan 2018)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-02 (HT208465)" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple memory corruption issues.

  - A validation issue." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system and read restricted memory." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.13.x prior to
  10.13.3, 10.12.x through 10.12.6 before build 16G1212 and 10.11.x through 10.11.6
  before build 15G19009." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208465" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[1-3]" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[1-3]" )){
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
				if(( osVer == "10.11.6" && version_is_less( version: buildVer, test_version: "15G19009" ) ) || ( osVer == "10.12.6" && version_is_less( version: buildVer, test_version: "16G1212" ) )){
					fix = "Apply patch from vendor";
					osVer = osVer + " Build " + buildVer;
				}
			}
		}
	}
}
else {
	if(version_in_range( version: osVer, test_version: "10.13", test_version2: "10.13.2" )){
		fix = "10.13.3";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

