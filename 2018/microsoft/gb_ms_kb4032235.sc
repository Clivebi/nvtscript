if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813286" );
	script_version( "2020-11-19T14:17:11+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-08-15 11:17:11 +0530 (Wed, 15 Aug 2018)" );
	script_name( "Microsoft Outlook 2016 Defense in Depth Vulnerability (KB4032235)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4032235" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft has released an update for
  Microsoft Office that provides enhanced security as a defense in depth
  measure." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to gain access to a system." );
	script_tag( name: "affected", value: "Microsoft Outlook 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4032235" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(!outlookVer || !IsMatchRegexp( outlookVer, "^16\\." )){
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
if(version_in_range( version: outlookVer, test_version: "16.0", test_version2: "16.0.4732.0999" )){
	report = report_fixed_ver( file_checked: outlookFile + "\\outlook.exe", file_version: outlookVer, vulnerable_range: "16.0 - 16.0.4732.0999" );
	security_message( data: report );
	exit( 0 );
}

