CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814631" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-8653" );
	script_bugtraq_id( 106255 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-12-20 15:06:56 +0530 (Thu, 20 Dec 2018)" );
	script_name( "Scripting Engine Memory Corruption Vulnerability (KB4483232)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4483232" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists because scripting engine
  improperly handles objects in memory in Internet Explorer." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user. An attacker who
  successfully exploited the vulnerability could gain the same user rights as the
  current user." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for 64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4483232" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "MS/IE/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win10: 1, win10x64: 1, win2016: 1 ) <= 0){
	exit( 0 );
}
ieVer = get_app_version( cpe: CPE, nofork: TRUE );
if(!ieVer || !IsMatchRegexp( ieVer, "^11\\." )){
	exit( 0 );
}
iePath = smb_get_system32root();
if(!iePath){
	exit( 0 );
}
iedllVer = fetch_file_version( sysPath: iePath, file_name: "Pcadm.dll" );
if(!iedllVer){
	exit( 0 );
}
if(version_in_range( version: iedllVer, test_version: "10.0.16299.0", test_version2: "10.0.16299.846" )){
	report = report_fixed_ver( file_checked: iePath + "\\Pcadm.dll", file_version: iedllVer, vulnerable_range: "10.0.16299.0 - 10.0.16299.847" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

