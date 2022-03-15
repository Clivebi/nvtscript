if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805448" );
	script_version( "2020-11-12T08:54:04+0000" );
	script_cve_id( "CVE-2015-0008" );
	script_bugtraq_id( 72477 );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-12 08:54:04 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-02-11 10:55:20 +0530 (Wed, 11 Feb 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Group Policy Remote Code Execution Vulnerability (3000483)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-011." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to remote code execution
  vulnerability in the way Group Policy receives and applies policy data if a
  domain-joined system is connected to a domain controller" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  context-dependent to execute arbitrary code. Failed exploit attempts will
  result in a denial-of-service condition." );
	script_tag( name: "affected", value: "- Microsoft Windows 2003 x32/x64 Service Pack 2

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32 Service Pack 2

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows Server 2008 x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3000483" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms15-011" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\drivers\\Dfsc.sys" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win2003x64: 3, win2003: 3 ) > 0){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
	if(version_is_less( version: sysVer, test_version: "6.0.6002.19279" ) || version_in_range( version: sysVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23587" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
	if(version_is_less( version: sysVer, test_version: "6.1.7601.18711" ) || version_in_range( version: sysVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22916" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
	if(version_is_less( version: sysVer, test_version: "6.2.9200.17225" ) || version_in_range( version: sysVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.21338" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
	if(version_is_less( version: sysVer, test_version: "6.3.9600.17630" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

