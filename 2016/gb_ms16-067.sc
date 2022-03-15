if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807325" );
	script_version( "2020-06-08T14:48:03+0000" );
	script_cve_id( "CVE-2016-0190" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-08 14:48:03 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-05-11 10:30:07 +0530 (Wed, 11 May 2016)" );
	script_name( "Microsoft Windows RDP Drive Information Disclosure Vulnerability (3155784)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-067" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when a USB disk mounted
  over Remote Desktop Protocol (RDP) via Microsoft RemoteFX is not correctly
  tied to the session of the mounting user." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to obtain access to file and directory information on the mounting
  user's USB disk." );
	script_tag( name: "affected", value: "- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3155784" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-067" );
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
if(hotfix_check_sp( win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "System32\\Drivers\\volmgr.sys" );
if(!sysVer){
	exit( 0 );
}
if( IsMatchRegexp( sysVer, "^(6\\.2\\.9200\\.2)" ) ){
	Vulnerable_range = "Less than - 6.2.9200.21831";
}
else {
	if(IsMatchRegexp( sysVer, "^(6\\.3\\.9600\\.1)" )){
		Vulnerable_range = "Less than 6.3.9600.18302";
	}
}
if( hotfix_check_sp( win2012: 1 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "6.2.9200.21831" )){
		VULN = TRUE;
	}
}
else {
	if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
		if(version_is_less( version: sysVer, test_version: "6.3.9600.18302" )){
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\system32\\Drivers\\volmgr.sys" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

