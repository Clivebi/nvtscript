if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814891" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_cve_id( "CVE-2019-8569", "CVE-2019-8592", "CVE-2019-8525", "CVE-2019-8547" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 15:03:00 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-05-14 10:43:25 +0530 (Tue, 14 May 2019)" );
	script_name( "Apple MacOSX Security Updates (HT210119) - 05" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to memory corruption
  issues with improper memory and error handling." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code
  with system privileges." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.12.x through
  10.12.6 and 10.13.x through 10.13.6." );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.12.6 build 16G2016
  or 10.13.6 build 17G7024 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT210119" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.1[23]\\." );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[23]\\." ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if(IsMatchRegexp( osVer, "^10\\.12" )){
	if( version_in_range( version: osVer, test_version: "10.12", test_version2: "10.12.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.12.6"){
			if(osVer == "10.12.6" && version_is_less( version: buildVer, test_version: "16G2016" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
if(IsMatchRegexp( osVer, "^10\\.13" )){
	if( version_in_range( version: osVer, test_version: "10.13", test_version2: "10.13.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.13.6"){
			if(osVer == "10.13.6" && version_is_less( version: buildVer, test_version: "17G7024" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

