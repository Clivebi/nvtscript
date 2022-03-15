if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901216" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-0078" );
	script_bugtraq_id( 58847 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-04-10 10:20:16 +0530 (Wed, 10 Apr 2013)" );
	script_name( "Microsoft Antimalware Client Privilege Elevation Vulnerability (2823482)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52921" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2781197" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-034" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code in the security context of the LocalSystem account." );
	script_tag( name: "affected", value: "Microsoft Windows Defender for Microsoft Windows 8." );
	script_tag( name: "insight", value: "Flaw is due to an unspecified error when improper pathnames are used
  by Windows Defender (Microsoft Antimalware Client)." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-034." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win8: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows Defender";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
program_files_path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!program_files_path){
	exit( 0 );
}
defender_ver = fetch_file_version( sysPath: program_files_path, file_name: "Windows Defender\\MSASCui.exe" );
if(!defender_ver){
	exit( 0 );
}
if(version_is_less( version: defender_ver, test_version: "4.2.223.0" )){
	report = report_fixed_ver( installed_version: defender_ver, fixed_version: "4.2.223.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

