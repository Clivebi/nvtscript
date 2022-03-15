if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815008" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_cve_id( "CVE-2019-8529", "CVE-2019-8504" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-30 19:45:00 +0000 (Mon, 30 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-03-26 15:43:26 +0530 (Tue, 26 Mar 2019)" );
	script_name( "Apple MacOSX Security Updates(HT209600)-03" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A memory corruption issue related to improper input validation.

  - A memory initialization issue related to improper memory handling." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to execute arbitrary code with kernel privileges and read kernel memory." );
	script_tag( name: "affected", value: "Apple Mac OS X versions,
  10.13.x through 10.13.6, 10.14.x through 10.14.3." );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.14.4 or later
  pr applyecurity Update 2019-002 High Sierra. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT209600" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[34]" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[34]" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if(IsMatchRegexp( osVer, "^10\\.13" )){
	if( version_in_range( version: osVer, test_version: "10.13", test_version2: "10.13.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.13.6"){
			if(version_is_less( version: buildVer, test_version: "17G6029" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
if(version_in_range( version: osVer, test_version: "10.14", test_version2: "10.14.3" )){
	fix = "10.14.4";
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

