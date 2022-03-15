if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816800" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_cve_id( "CVE-2020-0796" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-11 19:15:00 +0000 (Thu, 11 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-03-12 13:00:37 +0000 (Thu, 12 Mar 2020)" );
	script_name( "Microsoft Windows Server Message Block 3.1.1 RCE Vulnerability (KB4551762)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4551762" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to an error when the
  SMBv3 handles maliciously crafted compressed data packets. Both SMB Servers and
  clients are affected. To exploit the vulnerability against an SMB Server, an
  unauthenticated attacker could send a specially crafted packet to a targeted SMBv3
  Server. While as to exploit the vulnerability against an SMB Client, an
  unauthenticated attacker would need to configure a malicious SMBv3 Server and
  convince a user to connect to it." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute code on the target SMB Server or SMB Client." );
	script_tag( name: "affected", value: "SMB 3.1.1(SMBv3) on

  - Windows 10 Version 1903 for 32-bit/x64-based Systems

  - Windows 10 Version 1909 for 32-bit/x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-gb/help/4551762/" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "Gdiplus.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_in_range( version: fileVer, test_version: "10.0.18362.0", test_version2: "10.0.18362.719" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Gdiplus.dll", file_version: fileVer, vulnerable_range: "10.0.18362.0 - 10.0.18362.719" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

