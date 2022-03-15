if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813423" );
	script_version( "2020-06-04T11:13:22+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-04 11:13:22 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2018-06-13 09:16:14 +0530 (Wed, 13 Jun 2018)" );
	script_name( "Microsoft Office 2013 Service Pack 1 Defense in Depth (KB4018387)" );
	script_tag( name: "summary", value: "This host is missing a defense-in-depth update
  according to Microsoft KB4018387" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense in depth measure. This update
  improves the memory handling of Office applications that render Office Art." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass defense-in-depth measures and exploit Office applications that render
  Office Art." );
	script_tag( name: "affected", value: "Microsoft Office 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4018387" );
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
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
	}
}
for key in key_list {
	msPath = registry_get_sz( key: key, item: "ProgramFilesDir" );
	if(msPath){
		exePath = msPath + "\\Microsoft Office\\Office15";
		exeVer = fetch_file_version( sysPath: exePath, file_name: "oart.dll" );
		if(!exeVer){
			continue;
		}
		if(IsMatchRegexp( exeVer, "^15\\." ) && version_is_less( version: exeVer, test_version: "15.0.5041.1000" )){
			report = report_fixed_ver( file_checked: exePath + "\\oart.dll", file_version: exeVer, vulnerable_range: "15.0 - 15.0.5041.0999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

