if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901173" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-01-12 13:59:47 +0100 (Wed, 12 Jan 2011)" );
	script_cve_id( "CVE-2010-3145" );
	script_bugtraq_id( 42763 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Windows Backup Manager Remote Code Execution Vulnerability (2478935)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "Microsoft Windows Vista Service Pack 2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to the application insecurely loading certain
  libraries from the current working directory, which could allow attackers
  to execute arbitrary code and conduct DLL hijacking attacks via a Trojan
  horse fveapi.dll which is located in the same folder as a .wbcat file." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-001." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2478935" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/63788" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14751/" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-001" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2478935" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
exePath = sysPath + "\\system32\\Sdclt.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath );
exeVer = GetVer( file: file, share: share );
if(!exeVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3 ) > 0){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: exeVer, test_version: "6.0.6001.18561" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6001.18561", install_path: exePath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: exeVer, test_version: "6.0.6002.18353" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6002.18353", install_path: exePath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
