if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801715" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2011-01-14 09:03:25 +0100 (Fri, 14 Jan 2011)" );
	script_cve_id( "CVE-2007-2223" );
	script_bugtraq_id( 25301 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft XML Core Services Remote Code Execution Vulnerability (936227)" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2007/Aug/1018559.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-042" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attacker to execute arbitrary code in
  the context of the user running the application." );
	script_tag( name: "affected", value: "- Microsoft XML Core Services 3.0/4.0/5.0/6.0

  - Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista

  - Microsoft Office 2003 Service Pack 2

  - Microsoft Office 2007

  - Microsoft Office Compatibility Pack for Word/Excel/PowerPoint 2007 File Formats" );
	script_tag( name: "insight", value: "The flaw is due to an integer overflow error in the 'substringData()'
  method of an XMLDOM/TextNode JavaScript object." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS07-042." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
func FileVer( file, path ){
	share = ereg_replace( pattern: "([A-Za-z]):.*", replace: "\\1$", string: path );
	if(IsMatchRegexp( share, "[a-z]\\$" )){
		share = toupper( share );
	}
	file = ereg_replace( pattern: "[A-Za-z]:(.*)", replace: "\\1", string: path + file );
	ver = GetVer( file: file, share: share );
	return ver;
}
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^11\\." )){
	offPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(offPath){
		offPath += "\\Microsoft Shared\\OFFICE11";
		dllVer = FileVer( file: "\\msxml5.dll", path: offPath );
		if(dllVer){
			if(version_is_less( version: dllVer, test_version: "5.20.1081.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(officeVer && IsMatchRegexp( officeVer, "^12\\." )){
	offPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(offPath){
		offPath += "\\Microsoft Shared\\OFFICE12";
		dllVer = FileVer( file: "\\msxml5.dll", path: offPath );
		if(dllVer){
			if(version_is_less( version: dllVer, test_version: "5.20.1081.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Msxml3.dll" );
	dllVer2 = fetch_file_version( sysPath: sysPath, file_name: "Msxml4.dll" );
	dllVer3 = fetch_file_version( sysPath: sysPath, file_name: "Msxml6.dll" );
	if(dllVer || dllVer2 || dllVer3){
		if(!dllVer){
			dllVer = "unknown";
		}
		if(!dllVer2){
			dllVer2 = "unknown";
		}
		if(!dllVer3){
			dllVer3 = "unknown";
		}
		if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) > 0){
			if(version_in_range( version: dllVer, test_version: "8.0", test_version2: "8.90.1100.0" ) || version_in_range( version: dllVer2, test_version: "4.0", test_version2: "4.20.9847.0" ) || version_in_range( version: dllVer3, test_version: "6.0", test_version2: "6.10.1199.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", item: "PathName" );
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Msxml3.dll" );
dllVer2 = fetch_file_version( sysPath: sysPath, file_name: "system32\\Msxml4.dll" );
dllVer3 = fetch_file_version( sysPath: sysPath, file_name: "system32\\Msxml6.dll" );
if(dllVer || dllVer2 || dllVer3){
	if(!dllVer){
		dllVer = "unknown";
	}
	if(!dllVer2){
		dllVer2 = "unknown";
	}
	if(!dllVer3){
		dllVer3 = "unknown";
	}
	if(hotfix_check_sp( winVista: 3 ) > 0){
		if(version_in_range( version: dllVer, test_version: "8.0", test_version2: "8.90.1100.0" ) || version_in_range( version: dllVer2, test_version: "4.0", test_version2: "4.20.9847.0" ) || version_in_range( version: dllVer3, test_version: "6.0", test_version2: "6.10.1199.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
	if(hotfix_check_sp( win2008: 3 ) > 0){
		if(version_in_range( version: dllVer2, test_version: "4.0", test_version2: "4.20.9847.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

