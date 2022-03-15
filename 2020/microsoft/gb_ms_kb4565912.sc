if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817237" );
	script_version( "2021-08-12T06:00:50+0000" );
	script_cve_id( "CVE-2020-1346" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-16 12:57:00 +0000 (Thu, 16 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-16 13:21:55 +0530 (Thu, 16 Jul 2020)" );
	script_name( "Windows Modules Installer Elevation of Privilege Vulnerability (KB4565912)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4565912" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Windows Modules Installer
  fails to properly handle file operations.
  Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4565912" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1, win2016: 1 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "Ntoskrnl.exe" );
if(!fileVer){
	exit( 0 );
}
if(version_in_range( version: fileVer, test_version: "10.0.14393.0", test_version2: "10.0.14393.3807" )){
	report = report_fixed_ver( file_checked: dllPath + "\\Ntoskrnl.exe", file_version: fileVer, vulnerable_range: "10.0.14393.0 - 10.0.14393.3807" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

