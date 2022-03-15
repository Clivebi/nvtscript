if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900264" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)" );
	script_bugtraq_id( 45269 );
	script_cve_id( "CVE-2010-3963" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Routing and Remote Access Privilege Escalation Vulnerability (2440591)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2440591" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-099" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to bypass security
  restrictions and gain the privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to Routing and Remote Access NDProxy component which
  does not properly validate user-supplied input when passing data from user
  mode to the kernel." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS10-099." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2440591" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllPath = sysPath + "\\system32\\drivers\\Ndproxy.sys";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath );
dllVer = GetVer( file: file, share: share );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(( ContainsString( SP, "Service Pack 3" ) )){
		if(version_is_less( version: dllVer, test_version: "5.1.2600.6048" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.1.2600.6048", install_path: dllPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2003: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2003/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "5.2.3790.4795" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.2.3790.4795", install_path: dllPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

