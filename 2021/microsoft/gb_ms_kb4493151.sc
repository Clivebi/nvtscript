if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817680" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-27055" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-16 15:21:00 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 08:24:35 +0530 (Wed, 10 Mar 2021)" );
	script_name( "Microsoft Visio 2016 Security Feature Bypass Vulnerability (KB4493151" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4493151" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when a
  maliciously modified file is opened" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass security restrictions." );
	script_tag( name: "affected", value: "Microsoft Visio 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4493151" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\visio.exe", item: "Path" );
if(!sysPath){
	exit( 0 );
}
excelVer = fetch_file_version( sysPath: sysPath, file_name: "visio.exe" );
if(!excelVer){
	exit( 0 );
}
if(version_in_range( version: excelVer, test_version: "16.0", test_version2: "16.0.5134.0999" )){
	report = report_fixed_ver( file_checked: "visio.exe", file_version: excelVer, vulnerable_range: "16.0 - 16.0.5134.0999" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

