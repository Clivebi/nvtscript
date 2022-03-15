if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817734" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-34469" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-19 15:38:00 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-14 17:28:41 +0530 (Wed, 14 Jul 2021)" );
	script_name( "Microsoft Office 2016 RCE Vulnerability (KB5001979)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB5001979" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper input validation
  in Microsoft Office software." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Microsoft Office 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/5001979" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer || !IsMatchRegexp( officeVer, "^16\\." )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
	}
}
for key in key_list {
	msPath = registry_get_sz( key: key, item: "ProgramFilesDir" );
	if(msPath){
		offPath = msPath + "\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\Office16";
		offdllVer = fetch_file_version( sysPath: offPath, file_name: "mso.dll" );
		if(!offdllVer){
			continue;
		}
		if(IsMatchRegexp( offdllVer, "^16\\." ) && version_is_less( version: offdllVer, test_version: "16.0.5188.1000" )){
			report = report_fixed_ver( file_checked: msPath + "\\Microsoft Office\\Root\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\Office16\\Mso.dll", file_version: offdllVer, vulnerable_range: "16.0 - 16.0.5188.0999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

