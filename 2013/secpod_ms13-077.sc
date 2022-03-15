if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902993" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3862" );
	script_bugtraq_id( 62182 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-09-11 08:13:01 +0530 (Wed, 11 Sep 2013)" );
	script_name( "MS Windows Service Control Manager Privilege Elevation Vulnerability (2872339)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
Microsoft Bulletin MS13-077." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "The flaw is due to a double-free error in the Service Control Manager
(services.exe) when handling service descriptions from the registry." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
code with kernel-mode privileges within the context of the Service Control
Manager and or corrupt memory." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2872339" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-077" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Kernel32.dll" );
if(!exeVer){
	exit( 0 );
}
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
	if(version_is_less( version: exeVer, test_version: "6.1.7601.18229" ) || version_in_range( version: exeVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22410" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

