if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813573" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-8172", "CVE-2018-8232" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-12 13:08:27 +0530 (Thu, 12 Jul 2018)" );
	script_name( "Microsoft Visual Studio 2017 Multiple Vulnerabilities-July18" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Security Update." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - When the software fails to check the source markup of a file for an unbuilt
    project.

  - When Microsoft Macro Assembler improperly validates code logic." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to tamper the code and execute arbitrary code." );
	script_tag( name: "affected", value: "Microsoft Visual Studio 2017." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8172" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8232" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	key_list = make_list( "SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VS7",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\SxS\\VS7" );
	}
}
for key in key_list {
	installPath = registry_get_sz( key: key, item: "15.0" );
	if(!installPath){
		continue;
	}
	binPath = installPath + "Common7\\IDE\\PrivateAssemblies\\";
	dllVer = fetch_file_version( sysPath: binPath, file_name: "Microsoft.VisualStudio.Setup.dll" );
	if(dllVer && IsMatchRegexp( dllVer, "^1\\.1[56]\\." ) && version_is_less( version: dllVer, test_version: "1.16.1193.54969" )){
		report = report_fixed_ver( file_checked: binPath + "Microsoft.VisualStudio.Setup.dll", file_version: dllVer, vulnerable_range: "1.15.0 - 1.16.1193.54969" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

