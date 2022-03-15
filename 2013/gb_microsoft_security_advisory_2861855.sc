if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803867" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-08-17 16:25:19 +0530 (Sat, 17 Aug 2013)" );
	script_name( "Microsoft Remote Desktop Protocol Security Advisory (2861855)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
advisory (2861855)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is due to security issue in Network-level Authentication (NLA)
method in Remote Desktop Sessions." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass the security." );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2861855" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/advisory/2861855" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_smb_windows_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\drivers\\tssecsrv.sys" );
if( !exeVer ){
	exit( 0 );
}
else {
	if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
		if(version_is_less( version: exeVer, test_version: "6.0.6002.18868" ) || version_in_range( version: exeVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.23139" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
	if(version_is_less( version: exeVer, test_version: "6.1.7601.18186" ) || version_in_range( version: exeVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22360" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
