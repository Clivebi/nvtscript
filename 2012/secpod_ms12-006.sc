if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902900" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2011-3389" );
	script_bugtraq_id( 49778 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-01-11 09:47:46 +0530 (Wed, 11 Jan 2012)" );
	script_name( "Microsoft Windows SSL/TLS Information Disclosure Vulnerability (2643584)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2585542" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-006" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation of this issue may allow attackers to perform limited
  man-in-the-middle attacks to inject data into the beginning of the application protocol stream to execute HTTP
  transactions, bypass authentication." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "A flaw exists is due to an error in Microsoft Windows SChannel (Secure Channel),
  when modifying the way that the Windows Secure Channel (SChannel) component sends and receives encrypted network packets." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-006." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win7: 2, win2008: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
if(hotfix_check_sp( win2003: 3 ) > 0){
	if( hotfix_missing( name: "2585542" ) == 1 ){
		sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Schannel.dll" );
		if(sysVer){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_is_less( version: sysVer, test_version: "5.2.3790.4935" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
	else {
		if(hotfix_missing( name: "2638806" ) == 1){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
	exit( 0 );
}
if(hotfix_missing( name: "2585542" ) == 0){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Schannel.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 3" )){
		if(version_is_less( version: sysVer, test_version: "5.1.2600.6175" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
		SP = get_kb_item( "SMB/WinVista/ServicePack" );
		if(!SP){
			SP = get_kb_item( "SMB/Win2008/ServicePack" );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_in_range( version: sysVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18540" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22741" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win7: 2 ) > 0){
			if(version_is_less( version: sysVer, test_version: "6.1.7600.16915" ) || version_in_range( version: sysVer, test_version: "6.1.7600.21000", test_version2: "6.1.7600.21091" ) || version_in_range( version: sysVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17724" ) || version_in_range( version: sysVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21860" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

