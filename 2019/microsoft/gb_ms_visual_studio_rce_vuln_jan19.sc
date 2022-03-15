if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814662" );
	script_version( "2021-09-06T12:01:32+0000" );
	script_cve_id( "CVE-2019-0546" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-18 15:11:24 +0530 (Fri, 18 Jan 2019)" );
	script_name( "Microsoft Visual Studio Remote Code Execution Vulnerability Jan19" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Security Update January-2019." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when the Visual Studio C++
  compiler improperly handles specific combinations of C++ constructs." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to run arbitrary code in the context of the current user. If the
  current user is logged on with administrative user rights, an attacker could
  take control of the affected system." );
	script_tag( name: "affected", value: "Microsoft Visual Studio 2017 Version 15.9." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0546" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.9" );
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
			if(version_is_less( version: vsversion, test_version: "15.9.28307.280" )){
				report = report_fixed_ver( installed_version: vsversion, fixed_version: "Visual Studio 2017 version 15.9.28307.280" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

