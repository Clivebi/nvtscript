if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812610" );
	script_version( "2020-06-04T11:13:22+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-04 11:13:22 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2018-01-10 09:38:17 +0530 (Wed, 10 Jan 2018)" );
	script_name( "Microsoft Office 2016 Defense in Depth Update (KB4011622)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011622" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense-in-depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  affect on integrity, availability and confidentiality of the system." );
	script_tag( name: "affected", value: "Microsoft Office 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011622/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^16\\." )){
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
		propath = registry_get_sz( key: key, item: "ProgramFilesDir" );
		if(propath){
			offPath = propath + "\\Microsoft Office\\root\\VFS\\ProgramFilesCommonX86\\Microsoft Shared\\Office16";
			offexeVer = fetch_file_version( sysPath: offPath, file_name: "mso99lres.dll" );
			if(offexeVer && version_in_range( version: offexeVer, test_version: "16.0", test_version2: "16.0.4519.0999" )){
				report = report_fixed_ver( file_checked: offPath + "\\mso99lres.dll", file_version: offexeVer, vulnerable_range: "16.0 - 16.0.4519.0999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

