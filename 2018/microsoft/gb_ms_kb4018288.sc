if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813127" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-1026", "CVE-2018-1030" );
	script_bugtraq_id( 103613, 103620 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-04-11 09:46:16 +0530 (Wed, 11 Apr 2018)" );
	script_name( "Microsoft Office 2013 Service Pack 1 Multiple RCE Vulnerabilities (KB4018288)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4018288" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an error in
  Microsoft Office because it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4018288" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer || !IsMatchRegexp( officeVer, "^15\\." )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Office\\15.0\\Access\\InstallRoot" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Office\\15.0\\Access\\InstallRoot",
			 "SOFTWARE\\Microsoft\\Office\\15.0\\Access\\InstallRoot" );
	}
}
for key in key_list {
	comPath = registry_get_sz( key: key, item: "Path" );
	if(comPath){
		ortVer = fetch_file_version( sysPath: comPath, file_name: "Oart.dll" );
		if(ortVer && IsMatchRegexp( ortVer, "^15\\." )){
			if(version_is_less( version: ortVer, test_version: "15.0.5023.1000" )){
				report = report_fixed_ver( file_checked: comPath + "Oart.dll", file_version: ortVer, vulnerable_range: "15.0 - 15.0.5023.0999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

