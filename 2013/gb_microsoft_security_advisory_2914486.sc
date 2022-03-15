if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803971" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-5065" );
	script_bugtraq_id( 63971 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-12-02 15:40:48 +0530 (Mon, 02 Dec 2013)" );
	script_name( "Microsoft Windows Kernel Privilege Escalation Vulnerability (2914368)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-002" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is  due to an input validation error within the NDPROXY (NDProxy.sys)
  kernel component and can be exploited to execute arbitrary code with kernel privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain escalated
  privileges." );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2914368" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-002" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/advisory/2914486" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
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
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
win32SysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\drivers\\Ndproxy.sys" );
if(!win32SysVer){
	exit( 0 );
}
if(hotfix_check_sp( xp: 4 ) > 0){
	if(version_is_less( version: win32SysVer, test_version: "5.1.2600.6484" )){
		report = report_fixed_ver( installed_version: win32SysVer, fixed_version: "5.1.2600.6484", install_path: sysPath );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}
if(hotfix_check_sp( xpx64: 3, win2003x64: 3, win2003: 3 ) > 0){
	if(version_is_less( version: win32SysVer, test_version: "5.2.3790.5263" )){
		report = report_fixed_ver( installed_version: win32SysVer, fixed_version: "5.2.3790.5263", install_path: sysPath );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}

