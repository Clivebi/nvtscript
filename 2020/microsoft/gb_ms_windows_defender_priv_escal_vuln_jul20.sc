if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817314" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-1461" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-17 19:56:00 +0000 (Fri, 17 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-27 11:50:35 +0530 (Mon, 27 Jul 2020)" );
	script_name( "Microsoft Defender Elevation of Privilege Vulnerability-July 2020" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft July-2020 monthly updates." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  MpSigStub.exe for Defender which allows file deletion in arbitrary locations." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to escalate privileges and delete protected files on an affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows Defender on Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2019

  - Microsoft Windows Server 2016

  - Microsoft Windows 7 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 x32

  - Microsoft Windows Server 2008 R2 x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2" );
	script_tag( name: "solution", value: "Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1461" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1, win2016: 1, win2008: 3, win2019: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
mpsigstubVer = fetch_file_version( sysPath: sysPath, file_name: "mpsigstub.exe" );
if(!mpsigstubVer){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows Defender";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
def_version = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", item: "EngineVersion" );
if(!def_version){
	exit( 0 );
}
if(version_is_less( version: def_version, test_version: "1.1.17200.2" )){
	report = report_fixed_ver( installed_version: def_version, fixed_version: "1.1.17200.2 or higher" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

