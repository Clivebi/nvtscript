if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815235" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_cve_id( "CVE-2019-1084" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-04 14:14:00 +0000 (Mon, 04 May 2020)" );
	script_tag( name: "creation_date", value: "2019-07-10 13:14:58 +0530 (Wed, 10 Jul 2019)" );
	script_name( "Microsoft Outlook 2010 Service Pack 2 Information Disclosure Vulnerability (KB4475509)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4475509" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to creation of entities
  with Display Names having non-printable characters in Microsoft Outlook." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gather information about the victim." );
	script_tag( name: "affected", value: "Microsoft Outlook 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4475509/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(!outlookVer || !IsMatchRegexp( outlookVer, "^14\\." )){
	exit( 0 );
}
outlookFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\OUTLOOK.EXE", item: "Path" );
if(!outlookFile){
	exit( 0 );
}
outlookVer = fetch_file_version( sysPath: outlookFile, file_name: "outlook.exe" );
if(!outlookVer){
	exit( 0 );
}
if(version_in_range( version: outlookVer, test_version: "14.0", test_version2: "14.0.7235.4999" )){
	report = report_fixed_ver( file_checked: outlookFile + "outlook.exe", file_version: outlookVer, vulnerable_range: "14.0 - 14.0.7235.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

