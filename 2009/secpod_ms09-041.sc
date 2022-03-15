if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101102" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1544" );
	script_bugtraq_id( 35972 );
	script_name( "Vulnerability in Workstation Service Could Allow Elevation of Privilege (971657)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/971657" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2236" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-041" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges, and can cause Denial of Service." );
	script_tag( name: "affected", value: "- Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2k3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to a double free error while processing arguments
  passed to the 'NetrGetJoinInformation()' function. This can be exploited to
  trigger a memory corruption via a specially crafted RPC request." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-041." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "971657" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	wkssvcVer = fetch_file_version( sysPath: sysPath, file_name: "wkssvc.dll" );
	if(!wkssvcVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: wkssvcVer, test_version: "5.1.2600.3584" )){
			report = report_fixed_ver( installed_version: wkssvcVer, fixed_version: "5.1.2600.3584", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 3" )){
		if(version_is_less( version: wkssvcVer, test_version: "5.1.2600.5826" )){
			report = report_fixed_ver( installed_version: wkssvcVer, fixed_version: "5.1.2600.5826", install_path: sysPath );
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
			if(version_is_less( version: wkssvcVer, test_version: "5.2.3790.4530" )){
				report = report_fixed_ver( installed_version: wkssvcVer, fixed_version: "5.2.3790.4530", install_path: sysPath );
				security_message( port: 0, data: report );
			}
		}
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "wkssvc.dll" );
	if(!dllVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6001.18270" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18270", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6002.18049" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6002.18049", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2008: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: dllVer, test_version: "6.0.6001.18270" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18270", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "6.0.6002.18049" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6002.18049", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

