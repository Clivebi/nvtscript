if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811853" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-7149", "CVE-2017-7150" );
	script_bugtraq_id( 101178, 101177 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-10-09 10:57:39 +0530 (Mon, 09 Oct 2017)" );
	script_name( "Apple Mac OS X Multiple Information Disclosure Vulnerabilities-HT208165" );
	script_tag( name: "summary", value: "This host is has Apple Mac OS X and
  is prone to multiple information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - A method existed for applications to bypass the key chain access prompt with
    a synthetic click.

  - If a hint was set in Disk Utility when creating an APFS encrypted volume,
    the password was stored as the hint." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to access sensitive information like passwords and other important data." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.13 before
  build 17A405." );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X version
  10.13 build 17A405 by applying the supplemental update from the vendor." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208165" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.13" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.13" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
buildVer = get_kb_item( "ssh/login/osx_build" );
if(buildVer){
	if(revcomp( a: buildVer, b: "17A405" ) < 0){
		osVer = osVer + " Build " + buildVer;
		report = report_fixed_ver( installed_version: osVer, fixed_version: "Apply Supplemental Update for 10.13" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

