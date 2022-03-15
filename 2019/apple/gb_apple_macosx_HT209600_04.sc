if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815009" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_cve_id( "CVE-2019-8502", "CVE-2019-8546", "CVE-2019-8545", "CVE-2019-8542", "CVE-2019-8549", "CVE-2019-6237", "CVE-2019-6239", "CVE-2019-7293", "CVE-2019-8565", "CVE-2019-8519", "CVE-2019-8533", "CVE-2019-8511", "CVE-2019-8514", "CVE-2019-8517", "CVE-2019-8516", "CVE-2019-8537", "CVE-2019-8550", "CVE-2019-8552", "CVE-2019-8507" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-30 21:05:00 +0000 (Mon, 30 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-03-26 15:43:30 +0530 (Tue, 26 Mar 2019)" );
	script_name( "Apple MacOSX Security Updates(HT209600)-04" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An API issue existed in the handling of dictation requests.

  - An access issue related to sandbox restrictions.

  - A memory corruption issue related to improper state management.

  - A buffer overflow error improper bounds checking.

  - Multiple input validation issues existed in MIG generated code.

  - An out-of-bounds read related to improper bounds checking.

  - This issue related to improper handling of file metadata.

  - A memory corruption issue related to improper memory handling.

  - A race condition was addressed with additional validation.

  - A lock handling issue related to improper lock handling.

  - A buffer overflow issue related to improper memory handling.

  - A logic issue was addressed with improved state management.

  - A validation issue was addressed with improved logic.

  - An access issue was addressed with improved memory management.

  - An issue existed in the pausing of FaceTime video.

  - A memory initialization issue was addressed with improved memory handling.

  - Multiple memory corruption issues related to improper input validation." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to view sensitive user information, elevate privileges, cause unexpected system
  termination and execute arbitrary code." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.14.x through 10.14.3." );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.14.4 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT209600" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.14" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.14" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(version_in_range( version: osVer, test_version: "10.14", test_version2: "10.14.3" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "10.14.4" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

