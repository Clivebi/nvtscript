if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807587" );
	script_version( "2020-11-23T15:11:01+0000" );
	script_cve_id( "CVE-2016-0178" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-23 15:11:01 +0000 (Mon, 23 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-05-11 08:26:35 +0530 (Wed, 11 May 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS Windows Remote Privilege Escalation Vulnerability (3155520)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-061." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to when windows improperly
  handles specially crafted Remote Procedure Call (RPC) requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code with elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3153171" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-061" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
ntexeVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Ntoskrnl.exe" );
rpdllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Rpcrt4.dll" );
if(!ntexeVer && !rpdllVer){
	exit( 0 );
}
if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
	if( ntexeVer && version_is_less( version: ntexeVer, test_version: "6.3.9600.18289" ) ){
		Vulnerable_range = "Less than 6.3.9600.18289";
		VULN1 = TRUE;
	}
	else {
		if(rpdllVer && version_is_less( version: rpdllVer, test_version: "6.3.9600.18292" )){
			Vulnerable_range = "Less than 6.3.9600.18292";
			VULN2 = TRUE;
		}
	}
}
else {
	if(hotfix_check_sp( win2012: 1 ) > 0){
		if( ntexeVer && version_is_less( version: ntexeVer, test_version: "6.2.9200.21830" ) ){
			Vulnerable_range = "Less than 6.2.9200.21830";
			VULN1 = TRUE;
		}
		else {
			if(rpdllVer && version_is_less( version: rpdllVer, test_version: "6.2.9200.21826" )){
				Vulnerable_range = "Less than 6.2.9200.21826";
				VULN2 = TRUE;
			}
		}
	}
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if( ntexeVer && version_is_less( version: ntexeVer, test_version: "6.0.6002.19636" ) ){
		Vulnerable_range = "Less than 6.0.6002.19636";
		VULN1 = TRUE;
	}
	else {
		if(ntexeVer && version_in_range( version: ntexeVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23949" )){
			Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23949";
			VULN1 = TRUE;
		}
	}
}
else {
	if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
		if(ntexeVer && version_is_less( version: ntexeVer, test_version: "6.1.7601.23418" )){
			Vulnerable_range = "Less than 6.1.7601.23418";
			VULN1 = TRUE;
		}
	}
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	if( ntexeVer && version_is_less( version: ntexeVer, test_version: "10.0.10240.16841" ) ){
		Vulnerable_range = "Less than 10.0.10240.16841";
		VULN1 = TRUE;
	}
	else {
		if(ntexeVer && version_in_range( version: ntexeVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.305" )){
			Vulnerable_range = "10.0.10586.0 - 10.0.10586.305";
			VULN1 = TRUE;
		}
	}
}
if(VULN1){
	report = "File checked:     " + sysPath + "\\System32\\Ntoskrnl.exe" + "\n" + "File version:     " + ntexeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
if(VULN2){
	report = "File checked:     " + sysPath + "\\System32\\Rpcrt4.dll" + "\n" + "File version:     " + rpdllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

