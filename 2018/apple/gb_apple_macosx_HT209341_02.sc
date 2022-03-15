if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814605" );
	script_version( "2021-05-31T06:00:14+0200" );
	script_cve_id( "CVE-2018-4463", "CVE-2018-4460", "CVE-2018-4461", "CVE-2018-4434", "CVE-2018-4303" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:14 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 17:37:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-12-06 11:30:15 +0530 (Thu, 06 Dec 2018)" );
	script_name( "Apple MacOSX Security Updates(HT209341)-02" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A memory corruption issue was addressed with improved memory handling.

  - A denial of service issue was addressed by removing the vulnerable code.

  - A memory corruption issue was addressed with improved input validation.

  - An out-of-bounds read was addressed with improved input validation.

  - A type confusion issue was addressed with improved memory handling." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code with system privilegeS, perform a denial of service
  attack and a local user may be able to cause unexpected system termination or
  read kernel memory. A malicious application may be able to elevate privileges." );
	script_tag( name: "affected", value: "Apple Mac OS X versions,
  10.14.x through 10.14.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.14.2 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT209341" );
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
if(!osVer || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(version_in_range( version: osVer, test_version: "10.14", test_version2: "10.14.1" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "10.14.2" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

