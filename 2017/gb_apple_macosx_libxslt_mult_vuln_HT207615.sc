if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810981" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-2477" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-07 17:15:00 +0000 (Fri, 07 Apr 2017)" );
	script_tag( name: "creation_date", value: "2017-05-19 12:01:54 +0530 (Fri, 19 May 2017)" );
	script_name( "Apple Mac OS X 'libxslt' Multiple Vulnerabilities-HT207615" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple memory corruption vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  memory corruption issues causes due to poor memory handling." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to cause a denial of service (memory corruption) or possibly have unspecified
  other impact via unknown vectors." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.11.x through
  10.11.6" );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207615" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.11" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.11" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if( version_in_range( version: osVer, test_version: "10.11", test_version2: "10.11.5" ) ){
	fix = "Upgrade to latest OS release and apply patch from vendor";
}
else {
	if(version_is_equal( version: osVer, test_version: "10.11.6" )){
		buildVer = get_kb_item( "ssh/login/osx_build" );
		if(buildVer && version_is_less( version: buildVer, test_version: "15G1421" )){
			osVer = osVer + " Build " + buildVer;
			report = report_fixed_ver( installed_version: osVer, fixed_version: "Apply patch from vendor" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

