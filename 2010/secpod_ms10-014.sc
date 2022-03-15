if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902115" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)" );
	script_tag( name: "cvss_base", value: "6.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:C" );
	script_cve_id( "CVE-2010-0035" );
	script_bugtraq_id( 38110 );
	script_name( "Microsoft Kerberos Denial of Service Vulnerability (977290)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0344" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-014" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a vulnerable
  Windows domain controller to stop responding." );
	script_tag( name: "affected", value: "- Microsoft Windows 2000 Service Pack 4 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows 2008 Service Pack 3 and prior" );
	script_tag( name: "insight", value: "The issue is caused by a NULL pointer dereference error when handling
  'Ticket-Granting-Ticket' renewal requests sent by a client on a remote
   non-Windows realm in a mixed-mode Kerberos implementation." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to Microsoft
  Bulletin MS10-014." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "977290" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Kdcsvc.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "5.0.2195.7361" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
else {
	if( hotfix_check_sp( win2003: 3 ) > 0 ){
		SP = get_kb_item( "SMB/Win2003/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "5.2.3790.4628" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win2008: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2008/ServicePack" );
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_in_range( version: sysVer, test_version: "6.0.6001.18000", test_version2: "6.0.6001.18373" ) || version_in_range( version: sysVer, test_version: "6.0.6001.22000", test_version2: "6.0.6001.22573" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_in_range( version: sysVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18156" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22279" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

