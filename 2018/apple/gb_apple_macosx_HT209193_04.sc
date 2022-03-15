if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814424" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-4403", "CVE-2018-4424", "CVE-2018-4389" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 14:57:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-11-02 10:56:30 +0530 (Fri, 02 Nov 2018)" );
	script_name( "Apple MacOSX Security Updates(HT209193)-04" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An improper access restriction on files.

  - An input validation error.

  - An inconsistent user interface issue related to improper state management." );
	script_tag( name: "impact", value: "Successful exploitation allows remote
  attackers to conduct UI spoofing, execute arbitrary code and access restricted
  files." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.14" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.14.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT209193" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.14" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.14" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(osVer == "10.14"){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "10.14.1" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

