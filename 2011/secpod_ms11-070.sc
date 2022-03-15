if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902566" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)" );
	script_cve_id( "CVE-2011-1984" );
	script_bugtraq_id( 49523 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Windows WINS Local Privilege Escalation Vulnerability (2571621)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2571621" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17831/" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-070" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/ms-wins-ecommenddlg-input-validation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploits will allow local attackers to execute arbitrary code with
  local system privileges and potentially compromise the affected computer." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is caused by an error in the Windows Internet Name Service (WINS)
  when handling handling a series of malformed packets sent over the loopback
  interface, leading to arbitrary code execution with elevated privileges." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-070." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2571621" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
if(!registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\WINS" )){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Wins.exe" );
if(!exeVer){
	exit( 0 );
}
if( hotfix_check_sp( win2003: 3 ) > 0 ){
	SP = get_kb_item( "SMB/Win2003/ServicePack" );
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: exeVer, test_version: "5.2.3790.4893" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2008: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: exeVer, test_version: "6.0.6002.18501" ) || version_in_range( version: exeVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22692" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

