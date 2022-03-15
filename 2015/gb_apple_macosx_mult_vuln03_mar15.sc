if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805496" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-1066", "CVE-2015-1061" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-03-19 10:56:24 +0530 (Thu, 19 Mar 2015)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities -03 Mar15" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The off-by-one overflow condition in the IOAcceleratorFamily component that
    is triggered as user-supplied input is not properly validated

  - The flaw in IOSurface that is triggered during the handling of a specially
    crafted serialized object." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the targeted system, to conduct denial
  of service and local user can obtain root privileges on the target system." );
	script_tag( name: "affected", value: "Apple Mac OS X version through
  10.10.2" );
	script_tag( name: "solution", value: "Apply the fix from Apple Security Update
  2015-002." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT204413" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.([89]|10)" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.([89]|10)" )){
	exit( 0 );
}
if( version_in_range( version: osVer, test_version: "10.8", test_version2: "10.8.4" ) || version_in_range( version: osVer, test_version: "10.9", test_version2: "10.9.4" ) || version_in_range( version: osVer, test_version: "10.10", test_version2: "10.10.1" ) ){
	fix = "Upgrade to latest OS release and apply patch from vendor";
}
else {
	buildVer = get_kb_item( "ssh/login/osx_build" );
	if( buildVer && ( osVer == "10.8.5" && version_is_less( version: buildVer, test_version: "12F2501" ) ) ){
		fix = "Apply patch from vendor";
		osVer = osVer + " Build " + buildVer;
	}
	else {
		if( buildVer && ( osVer == "10.9.5" && version_is_less( version: buildVer, test_version: "13F1066" ) ) ){
			fix = "Apply patch from vendor";
			osVer = osVer + " Build " + buildVer;
		}
		else {
			if(buildVer && ( osVer == "10.10.2" && version_is_less( version: buildVer, test_version: "14C1510" ) )){
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

