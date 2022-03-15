if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814767" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-0809" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-10 03:01:00 +0000 (Wed, 10 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-03-13 16:24:43 +0530 (Wed, 13 Mar 2019)" );
	script_name( "Microsoft Visual Studio Remote Code Execution Vulnerability Mar19" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Security Update March-2019." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when the
  Visual Studio C++ Redistributable Installer improperly validates input before
  loading dynamic link library (DLL) files." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Visual Studio 2017 Version 15.9." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0809" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_visual_prdts_detect.sc" );
	script_mandatory_keys( "Microsoft/VisualStudio/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
vsVer = get_kb_item( "Microsoft/VisualStudio/Ver" );
if(!vsVer || !IsMatchRegexp( vsVer, "^15\\." )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		vsname = registry_get_sz( key: key + item, item: "DisplayName" );
		if(IsMatchRegexp( vsname, "^Visual Studio.*2017$" )){
			vsversion = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(!vsversion){
				exit( 0 );
			}
			if(version_in_range( version: vsversion, test_version: "15.9", test_version2: "15.9.28307.518" )){
				report = report_fixed_ver( installed_version: vsversion, fixed_version: "Visual Studio 2017 version 15.9.9" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

