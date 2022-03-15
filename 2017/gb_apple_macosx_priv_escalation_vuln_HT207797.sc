if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810985" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_cve_id( "CVE-2017-2533" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-25 01:29:00 +0000 (Wed, 25 Oct 2017)" );
	script_tag( name: "creation_date", value: "2017-05-16 15:41:39 +0530 (Tue, 16 May 2017)" );
	script_name( "Apple Mac OS X Privilege Escalation Vulnerability-HT207797" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to poor filesystem
  restrictions" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to gain system privileges." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.11.x through
  10.11.6 and 10.12.x through 10.12.4" );
	script_tag( name: "solution", value: "For Apple Mac OS X version 10.12.x before
  10.12.4 update to 10.12.5 and for versions 10.11.x through 10.11.6 apply the
  appropriate security patch described in the references." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207797" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( osVer, "^10\\.11" ) ){
	if( version_in_range( version: osVer, test_version: "10.11", test_version2: "10.11.5" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(version_is_equal( version: osVer, test_version: "10.11.6" )){
			buildVer = get_kb_item( "ssh/login/osx_build" );
			if(buildVer && version_is_less( version: buildVer, test_version: "15G1510" )){
				fix = "Apply patch from vendor";
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

