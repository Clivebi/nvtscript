if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811207" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_cve_id( "CVE-2017-8461" );
	script_bugtraq_id( 99012 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-29 14:07:00 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-06-16 15:56:08 +0530 (Fri, 16 Jun 2017)" );
	script_name( "Microsoft Windows 'RPC' Remote Code Execution Vulnerability (KB4024323)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4024323" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the way
  RPC service handles requests while the server has routing and remote access
  enabled." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of current user." );
	script_tag( name: "affected", value: "- Microsoft Windows XP SP2 x64

  - Microsoft Windows XP SP3 x86

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4024323" );
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
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
winVer = fetch_file_version( sysPath: sysPath, file_name: "Rasdlg.dll" );
if(!winVer){
	exit( 0 );
}
if(hotfix_check_sp( xp: 4 ) > 0){
	if(version_is_less( version: winVer, test_version: "5.1.2600.7272" )){
		Vulnerable_range = "Less than 5.1.2600.7272";
		VULN = TRUE;
	}
}
if(hotfix_check_sp( win2003: 3, win2003x64: 3, xpx64: 3 ) > 0){
	if(version_is_less( version: winVer, test_version: "5.2.3790.6099" )){
		Vulnerable_range = "Less than 5.2.3790.6099";
		VULN = TRUE;
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\Rasdlg.dll" + "\n" + "File version:     " + winVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

