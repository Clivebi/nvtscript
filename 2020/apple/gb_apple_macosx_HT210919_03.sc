if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816619" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3866", "CVE-2020-3840", "CVE-2020-3872", "CVE-2020-3839", "CVE-2020-3837", "CVE-2020-3854", "CVE-2020-3857", "CVE-2020-3877" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-02 20:52:00 +0000 (Mon, 02 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-01-29 14:38:26 +0530 (Wed, 29 Jan 2020)" );
	script_name( "Apple Mac OS X Security Update (HT210919) - 03" );
	script_tag( name: "summary", value: "Apple Mac OS X is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Missing checks by Gatekeeper on files mounted through a network share.

  - An off by one issue existed in the handling of racoon configuration files.

  - A memory initialization issue related to improper memory handling.

  - A validation issue related to improper input sanitization.

  - A memory corruption issue related to improper memory handling.

  - An out-of-bounds read error related to improper input validation." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to conduct arbitrary code execution, read restricted memory and cause denial
  of service." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.15.x through 10.15.2" );
	script_tag( name: "solution", value: "Update to Apple Mac OS X 10.15.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT210919" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(!osVer || !IsMatchRegexp( osVer, "^10\\.15" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(version_in_range( version: osVer, test_version: "10.15", test_version2: "10.15.2" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "10.15.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

