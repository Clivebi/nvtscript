if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900296" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)" );
	script_bugtraq_id( 48987, 48990 );
	script_cve_id( "CVE-2011-1871", "CVE-2011-1965" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Microsoft Windows TCP/IP Stack Denial of Service Vulnerability (2563894)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2563894" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-064" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attacker to cause the system to
  stop responding and automatically restart." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaws are due to errors the TCP/IP stack,

  - when parsing specially crafted URLs.

  - when processing  a sequence of specially crafted ICMP messages." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-064." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win2008: 3, win7: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2563894" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "\\system32\\drivers\\tcpip.sys" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(!SP){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_in_range( version: sysVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18483" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22661" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win7: 2 ) > 0){
		if(version_in_range( version: sysVer, test_version: "6.1.7600.16000", test_version2: "6.1.7600.16838" ) || version_in_range( version: sysVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.20991" ) || version_in_range( version: sysVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17637" ) || version_in_range( version: sysVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21753" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

