if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900265" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)" );
	script_bugtraq_id( 45318 );
	script_cve_id( "CVE-2010-3961" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Consent User Interface Privilege Escalation Vulnerability (2442962)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2442962" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-100" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to bypass security
  restrictions and gain the privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "Consent UI does not properly process a registry key that has been set to a
  specific value." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-100." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win2008: 3, win7: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2442962" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllPath = sysPath + "\\system32\\Consent.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath );
dllVer = GetVer( file: file, share: share );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(!SP){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
	}
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6001.18539" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18539", install_path: dllPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6002.18328" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6002.18328", install_path: dllPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win7: 1 ) > 0){
		if(version_is_less( version: dllVer, test_version: "6.1.7600.16688" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.1.7600.16688", install_path: dllPath );
			security_message( port: 0, data: report );
		}
	}
}

