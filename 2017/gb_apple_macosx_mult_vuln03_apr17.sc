if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810931" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_cve_id( "CVE-2010-0543", "CVE-2010-1375" );
	script_bugtraq_id( 40894, 40901 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-04-18 11:40:44 +0530 (Tue, 18 Apr 2017)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-03 April-2017" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A memory corruption exists in the handling of MPEG2 encoded movie files.

  - NetAuthSysAgent does not require authorization for certain operations." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to cause an unexpected application termination or arbitrary code execution and
  escalate privileges." );
	script_tag( name: "affected", value: "Apple Mac OS X and Mac OS X Server
  version 10.5.8" );
	script_tag( name: "solution", value: "Apply the appropriate patch from the
  referenced link." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "30" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT4188" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.5" );
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
	if(version_in_range( version: osVer, test_version: "10.5", test_version2: "10.5.8" )){
		report = report_fixed_ver( installed_version: osVer, fixed_version: "Apply the appropriate patch" );
		security_message( data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

