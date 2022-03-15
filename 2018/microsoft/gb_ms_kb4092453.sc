if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814122" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-8501" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-10 11:31:01 +0530 (Wed, 10 Oct 2018)" );
	script_name( "Microsoft PowerPoint 2013 Service Pack 1 Remote Code Execution Vulnerability (KB4092453)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4092453" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in Microsoft PowerPoint
  when the software fails to properly handle objects in Protected View." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft PowerPoint 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4092453" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/PowerPnt/Version", "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
pptVer = get_kb_item( "SMB/Office/PowerPnt/Version" );
if(!pptVer){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!path){
	exit( 0 );
}
offPath = path + "\\Microsoft Office\\OFFICE15";
exeVer = fetch_file_version( sysPath: offPath, file_name: "ppcore.dll" );
if(!exeVer){
	exit( 0 );
}
if(IsMatchRegexp( exeVer, "^15\\." ) && version_is_less( version: exeVer, test_version: "15.0.5075.1000" )){
	report = report_fixed_ver( file_checked: offPath + "\\ppcore.dll", file_version: exeVer, vulnerable_range: "15.0 - 15.0.5075.0999" );
	security_message( data: report );
}

