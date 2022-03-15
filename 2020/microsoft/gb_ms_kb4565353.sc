if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817241" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-1346" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-16 12:57:00 +0000 (Thu, 16 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-16 15:13:23 +0530 (Thu, 16 Jul 2020)" );
	script_name( "Windows Modules Installer Elevation of Privilege Vulnerability (KB4565353)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4565353" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Windows Modules Installer
  fails to properly handle file operations.
  Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2008 for 32-bit Systems Service Pack 2

  - Microsoft Windows Server 2008 for x64-based Systems Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4565353" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "Cmitrust.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.0.6003.20877" )){
	report = report_fixed_ver( file_checked: dllPath + "\\Cmitrust.dll", file_version: fileVer, vulnerable_range: "Less than 6.0.6003.20877" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

