if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806151" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-4459", "CVE-2014-4458" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-10-29 14:23:09 +0530 (Thu, 29 Oct 2015)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-06 October-15" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist in WebKit and
  the 'System Profiler About This Mac' component." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code via crafted page objects in an HTML document." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.x before
  10.10.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X version
  10.10.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2014/Nov/msg00001.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.([0-9]|10)\\." );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(ContainsString( osName, "Mac OS X" )){
	if(IsMatchRegexp( osVer, "^10\\.([0-9]|10)\\." ) && version_is_less( version: osVer, test_version: "10.10.1" )){
		report = report_fixed_ver( installed_version: osVer, fixed_version: "10.10.1" );
		security_message( data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

