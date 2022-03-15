if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903419" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-5054" );
	script_bugtraq_id( 64092 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-11 11:06:48 +0530 (Wed, 11 Dec 2013)" );
	script_name( "Microsoft Office Information Disclosure Vulnerability (2909976)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-104." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "The flaw is due to the application improperly handling response while
  attempting to open a hosted file and can be exploited to disclose tokens
  used to authenticate the user on a SharePoint or other Microsoft Office
  server site." );
	script_tag( name: "affected", value: "Microsoft Office 2013." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to disclose certain
  sensitive information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2850064" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1029464" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-104" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
offVer = get_kb_item( "MS/Office/Ver" );
if(!offVer){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(!path){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^15.*" )){
	filePath = path + "\\Microsoft Shared\\OFFICE15";
	fileVer = fetch_file_version( sysPath: filePath, file_name: "Msores.dll" );
	if(fileVer){
		if(version_in_range( version: fileVer, test_version: "15.0", test_version2: "15.0.4551.1000" )){
			report = report_fixed_ver( installed_version: fileVer, vulnerable_range: "15.0 - 15.0.4551.1000", install_path: filePath );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}

