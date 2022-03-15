if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811029" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_cve_id( "CVE-2017-0077" );
	script_bugtraq_id( 98114 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-10 10:56:24 +0530 (Wed, 10 May 2017)" );
	script_name( "Microsoft Windows 'Dxgkrnl.sys' Elevation of Privilege Vulnerability (KB4019149)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4019149." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in the way
  Microsoft DirectX graphics kernel subsystem (dxgkrnl.sys) handles certain calls
  and escapes to preclude improper memory mapping and prevent unintended elevation
  from user-mode." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to take control over the affected system and run processes in an elevated context." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4019149" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0077" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
winVer = fetch_file_version( sysPath: sysPath, file_name: "Dxgkrnl.sys" );
if(!winVer){
	exit( 0 );
}
if( version_is_less( version: winVer, test_version: "7.0.6002.19765" ) ){
	Vulnerable_range = "Less than 7.0.6002.19765";
	VULN = TRUE;
}
else {
	if(version_in_range( version: winVer, test_version: "6.0.6002.23000", test_version2: "7.0.6002.24088" )){
		Vulnerable_range = "6.0.6002.23000 - 7.0.6002.24088";
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\Dxgkrnl.sys" + "\n" + "File version:     " + winVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );
