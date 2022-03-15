if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813417" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-8246" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-06 18:49:00 +0000 (Mon, 06 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-13 08:25:13 +0530 (Wed, 13 Jun 2018)" );
	script_name( "Microsoft Office Compatibility Pack Service Pack 3 Information Disclosure Vulnerability (KB4022196)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4022196" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when Microsoft
  Excel improperly discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to potentially sensitive information which can be used to
  compromise the user's computer or data." );
	script_tag( name: "affected", value: "Microsoft Office Compatibility Pack Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4022196" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/ComptPack/Version" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
cmpPckVer = get_kb_item( "SMB/Office/ComptPack/Version" );
if(cmpPckVer && IsMatchRegexp( cmpPckVer, "^12\\." )){
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
			xlcnvVer = get_kb_item( "SMB/Office/XLCnv/Version" );
			if(xlcnvVer && IsMatchRegexp( xlcnvVer, "^12\\." )){
				offpath = msPath + "\\Microsoft Office\\Office12";
				sysVer = fetch_file_version( sysPath: offpath, file_name: "excelcnv.exe" );
				if(sysVer && IsMatchRegexp( sysVer, "^12\\." ) && version_in_range( version: sysVer, test_version: "12.0", test_version2: "12.0.6800.4999" )){
					report = report_fixed_ver( file_checked: offpath + "\\excelcnv.exe", file_version: sysVer, vulnerable_range: "12.0 - 12.0.6800.4999" );
					security_message( data: report );
					exit( 0 );
				}
			}
		}
	}
}
exit( 0 );

