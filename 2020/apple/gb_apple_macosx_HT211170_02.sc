if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817131" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9837", "CVE-2020-9842" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-09 23:51:00 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-05-27 12:16:58 +0530 (Wed, 27 May 2020)" );
	script_name( "Apple Mac OS X Security Update (HT211170 - 02)" );
	script_tag( name: "summary", value: "Apple Mac OS X is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An out-of-bounds read error.

  - An entitlement parsing issue." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to leak memory, access private information and perform privileged
  actions." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.13.x through
  10.13.6, 10.15.x through 10.15.4" );
	script_tag( name: "solution", value: "Apply security update 2020-003 for Apple Mac OS X
  version 10.13.x or upgrade to version 10.15.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT211170" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(!osVer || !IsMatchRegexp( osVer, "^10\\.1[35]" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if( IsMatchRegexp( osVer, "^10\\.13" ) ){
	if( version_in_range( version: osVer, test_version: "10.13", test_version2: "10.13.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.13.6"){
			if(osVer == "10.13.6" && version_is_less( version: buildVer, test_version: "17G13033" )){
				fix = "Apply patch from vendor";
				osVer = osVer + " Build " + buildVer;
			}
		}
	}
}
else {
	if(version_in_range( version: osVer, test_version: "10.15", test_version2: "10.15.4" )){
		fix = "10.15.5";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: osVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

