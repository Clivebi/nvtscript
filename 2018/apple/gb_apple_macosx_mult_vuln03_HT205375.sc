if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813193" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-5944", "CVE-2015-5935", "CVE-2015-5938" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2018-05-15 15:17:32 +0530 (Tue, 15 May 2018)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-03 (HT205375)" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple
  memory corruption issues." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.9.x through
  10.9.5 prior to build 13F1134, 10.10.x through 10.10.5 prior to build 14F1021" );
	script_tag( name: "solution", value: "Apply the appropriate patch. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT205375" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.(9|10)" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.(9|10)" )){
	exit( 0 );
}
if(IsMatchRegexp( osVer, "^10\\.(9|10)" )){
	if( version_in_range( version: osVer, test_version: "10.9", test_version2: "10.9.4" ) || version_in_range( version: osVer, test_version: "10.10", test_version2: "10.10.4" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.9.5" || osVer == "10.10.5"){
			buildVer = get_kb_item( "ssh/login/osx_build" );
			if(buildVer){
				if(( osVer == "10.9.5" && version_is_less( version: buildVer, test_version: "13F1134" ) ) || ( osVer == "10.10.5" && version_is_less( version: buildVer, test_version: "14F1021" ) )){
					fix = "Apply patch from vendor";
					osVer = osVer + " Build " + buildVer;
				}
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

