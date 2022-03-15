if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814894" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_cve_id( "CVE-2019-0708" );
	script_bugtraq_id( 108273 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 18:15:00 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-05-17 15:27:29 +0530 (Fri, 17 May 2019)" );
	script_name( "Microsoft Windows Remote Desktop Service Remote Code Execution Vulnerability (KB4500331)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4500331." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists when an unauthenticated attacker
  connects to the system using RDP and sends specially crafted requests. The vulnerability
  is known as 'BlueKeep'." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to
  execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "- Microsoft Windows XP SP3

  - Microsoft Windows Server 2003 SP2

  - Microsoft Windows XP Professional x64 Edition SP2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/help/4500331/windows-update-kb4500331" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "\\drivers\\Termdd.sys" );
if(!fileVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: fileVer, test_version: "5.1.2600.7701" )){
		report = report_fixed_ver( file_checked: sysPath + "\\drivers\\Termdd.sys", file_version: fileVer, vulnerable_range: "Less than 5.1.2600.7701" );
		security_message( data: report );
		exit( 0 );
	}
}
else {
	if(hotfix_check_sp( win2003: 3, win2003x64: 3, xpx64: 3 ) > 0){
		if(version_is_less( version: fileVer, test_version: "5.2.3790.6787" )){
			report = report_fixed_ver( file_checked: sysPath + "\\drivers\\Termdd.sys", file_version: fileVer, vulnerable_range: "Less than 5.2.3790.6787" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

