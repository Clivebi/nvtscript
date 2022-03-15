if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802078" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-0316" );
	script_bugtraq_id( 69097 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-08-13 08:52:09 +0530 (Wed, 13 Aug 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft Windows RPC Security Feature Bypass Vulnerability (2978668)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-047" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to RPC improperly frees messages that the server rejects as
  malformed, allowing an attacker to fill up the address space of a process." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass the ASLR
  security feature in conjunction with another vulnerability." );
	script_tag( name: "affected", value: "- Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2978668" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-047" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8: 1, win8x64: 1, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
Rpcrt4Ver = fetch_file_version( sysPath: sysPath, file_name: "system32\\Rpcrt4.dll" );
if(!Rpcrt4Ver){
	exit( 0 );
}
if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
	if(version_is_less( version: Rpcrt4Ver, test_version: "6.1.7601.18532" ) || version_in_range( version: Rpcrt4Ver, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22742" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
		if(version_is_less( version: Rpcrt4Ver, test_version: "6.2.9200.17037" ) || version_in_range( version: Rpcrt4Ver, test_version: "6.2.9200.20000", test_version2: "6.2.9200.21153" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
	if(version_is_less( version: Rpcrt4Ver, test_version: "6.3.9600.17216" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

