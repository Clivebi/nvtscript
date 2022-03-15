if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812848" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-1038" );
	script_bugtraq_id( 103549 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-03-30 13:47:55 +0530 (Fri, 30 Mar 2018)" );
	script_name( "Microsoft Windows Kernel Elevation of Privilege Vulnerability (KB4100480)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4100480" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Windows kernel failing
  to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode which will empower them to install
  programs, view, change, delete data or create new accounts with full user
  rights." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 for x64-based Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4100480" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "kernel32.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.1.7601.24059" )){
	report = report_fixed_ver( file_checked: sysPath + "\\kernel32.dll", file_version: fileVer, vulnerable_range: "Less than 6.1.7601.24059" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

