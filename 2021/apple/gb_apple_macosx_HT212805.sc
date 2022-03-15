if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818524" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-30860" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-14 15:42:00 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-14 18:07:04 +0530 (Tue, 14 Sep 2021)" );
	script_name( "Apple MacOSX Security Update (HT212805)" );
	script_tag( name: "summary", value: "Apple Mac OS X is prone to an arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an integer overflow error
  related with improper input validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Apple Mac OS X 10.15.x prior to
  Security Update 2021-005 Catalina." );
	script_tag( name: "solution", value: "Apply Security Update 2021-005 for 10.15.x.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212805" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(!osVer || !IsMatchRegexp( osVer, "^10\\.15\\." ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if(IsMatchRegexp( osVer, "^10\\.15" )){
	if( version_in_range( version: osVer, test_version: "10.15", test_version2: "10.15.6" ) ){
		fix = "Upgrade to latest OS release and apply patch from vendor";
	}
	else {
		if(osVer == "10.15.7"){
			if(version_is_less( version: buildVer, test_version: "19H1417" )){
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

