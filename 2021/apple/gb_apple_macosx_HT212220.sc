if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817973" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-1844" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-31 00:15:00 +0000 (Mon, 31 May 2021)" );
	script_tag( name: "creation_date", value: "2021-03-12 15:19:26 +0530 (Fri, 12 Mar 2021)" );
	script_name( "Apple MacOSX Security Update (HT212220)" );
	script_tag( name: "summary", value: "Apple Mac OS X is prone to a memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a memory corruption error
  related to improper validation." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct arbitrary code execution." );
	script_tag( name: "affected", value: "Apple Mac OS X Big Sur versions 11.x before
  11.2.3." );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X Big Sur version
  11.2.3 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212220" );
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
if(!osVer || !IsMatchRegexp( osVer, "^11\\." ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(version_in_range( version: osVer, test_version: "11.0", test_version2: "11.2.2" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "11.2.3" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

