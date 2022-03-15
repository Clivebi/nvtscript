if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817493" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_cve_id( "CVE-2020-16949", "CVE-2020-16947" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-22 16:49:00 +0000 (Thu, 22 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-14 08:49:58 +0530 (Wed, 14 Oct 2020)" );
	script_name( "Microsoft Outlook 2016 Denial of Service And Remote Code Execution Vulnerabilities (KB4486671)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4486671" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to Microsoft Outlook
  software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the System user and cause remote denial
  of service against a system." );
	script_tag( name: "affected", value: "Microsoft Outlook 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4486671" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
outlookFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\OUTLOOK.EXE", item: "Path" );
if(!outlookFile){
	exit( 0 );
}
outlookVer = fetch_file_version( sysPath: outlookFile, file_name: "outlook.exe" );
if(!outlookVer){
	exit( 0 );
}
if(version_in_range( version: outlookVer, test_version: "16.0", test_version2: "16.0.5071.0999" )){
	report = report_fixed_ver( file_checked: outlookFile + "outlook.exe", file_version: outlookVer, vulnerable_range: "16.0 - 16.0.5071.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

