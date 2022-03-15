if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811817" );
	script_version( "2020-06-04T12:11:49+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-04 12:11:49 +0000 (Thu, 04 Jun 2020)" );
	script_tag( name: "creation_date", value: "2017-09-13 10:05:57 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Outlook 2013 Defense in Depth Update (KB4011090)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011090" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft has released an update for
  Microsoft Office that provides enhanced security as a defense-in-depth measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to compromise on availability, confidentiality and integrity of the system." );
	script_tag( name: "affected", value: "Microsoft Outlook 2013." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011090" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Outlook/Version" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
outlookVer = get_kb_item( "SMB/Office/Outlook/Version" );
if(!outlookVer || !IsMatchRegexp( outlookVer, "^15\\." )){
	exit( 0 );
}
outlookFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\OUTLOOK.EXE", item: "Path" );
if(!outlookFile){
	exit( 0 );
}
outlookVer = fetch_file_version( sysPath: outlookFile, file_name: "outlook.exe" );
if(!outlookVer){
	exit( 0 );
}
if(version_in_range( version: outlookVer, test_version: "15.0", test_version2: "15.0.4963.0999" )){
	report = "File checked:     " + outlookFile + "\\outlook.exe" + "\n" + "File version:     " + outlookVer + "\n" + "Vulnerable range:  15.0 - 15.0.4963.0999" + "\n";
	security_message( data: report );
	exit( 0 );
}

