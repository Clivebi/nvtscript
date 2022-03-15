if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805036" );
	script_version( "2021-05-06T09:11:05+0000" );
	script_cve_id( "CVE-2015-0006" );
	script_bugtraq_id( 71930 );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:C/A:N" );
	script_tag( name: "last_modification", value: "2021-05-06 09:11:05 +0000 (Thu, 06 May 2021)" );
	script_tag( name: "creation_date", value: "2015-01-14 08:53:24 +0530 (Wed, 14 Jan 2015)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MS Windows Network Location Awareness Service Security Bypass Vulnerability (3022777)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-005." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error within the
  Network Location Awareness (NLA) service when validating if a domain-connected
  computer is connected to the domain." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to relax the firewall policy and/or configuration of certain
  services by spoofing responses of DNS or LDAP traffic via a
  Man-in-the-Middle attack." );
	script_tag( name: "affected", value: "- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/topic/ms15-005-vulnerability-in-network-location-awareness-service-could-allow-security-feature-bypass-january-13-2015-5a2f60a5-f721-4e2c-2a52-c4a8dd4c3b95" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-005" );
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
if(hotfix_check_sp( win2003x64: 3, win2003: 3 ) > 0){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ncsi.dll" );
if(!dllVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.0.6002.19250" ) || version_in_range( version: dllVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23556" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.1.7601.17964" ) || version_in_range( version: dllVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22892" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.2.9200.17199" ) || version_in_range( version: dllVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.20622" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.3.9600.17550" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

