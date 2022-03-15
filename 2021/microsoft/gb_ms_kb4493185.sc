if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817995" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-28452" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-19 23:32:00 +0000 (Mon, 19 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-15 11:24:37 +0530 (Thu, 15 Apr 2021)" );
	script_name( "Microsoft Outlook 2010 Memory Corruption Vulnerability (KB4493185)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4493185" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a memory corruption error
  in Microsoft Outlook software." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct remote code execution and may cause other impacts." );
	script_tag( name: "affected", value: "Microsoft Outlook 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4493185" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(!outlookVer){
	exit( 0 );
}
outlookFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\OUTLOOK.EXE", item: "Path" );
if(!outlookFile){
	exit( 0 );
}
outlookVer = fetch_file_version( sysPath: outlookFile, file_name: "olmapi32.dll" );
if(!outlookVer){
	exit( 0 );
}
if(version_in_range( version: outlookVer, test_version: "14.0", test_version2: "14.0.7268.4999" )){
	report = report_fixed_ver( file_checked: outlookFile + "olmapi32.dll", file_version: outlookVer, vulnerable_range: "14.0 - 14.0.7268.4999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

