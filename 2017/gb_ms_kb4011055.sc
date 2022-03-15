if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811335" );
	script_version( "2020-06-04T12:11:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-04 12:11:49 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2017-09-13 16:22:54 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Office 2013 Defense in Depth Update (KB4011103)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011103" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft has released an update for Microsoft
  Office that provides enhanced security as a defense-in-depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  compromise availability, integrity, and confidentiality of the system." );
	script_tag( name: "affected", value: "Microsoft Office 2013." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011103" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!officeVer){
	exit( 0 );
}
commonpath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(!commonpath){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^(15\\.)" )){
	offPath = commonpath + "\\Microsoft Shared\\Office15";
	offexeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
	if(offexeVer && version_in_range( version: offexeVer, test_version: "15.0", test_version2: "15.0.4963.1001" )){
		report = "File checked:     " + offPath + "\\Mso.dll" + "\n" + "File version:     " + offexeVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4963.1001" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

