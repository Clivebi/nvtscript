if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811753" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_cve_id( "CVE-2017-8742", "CVE-2017-8743" );
	script_bugtraq_id( 100741, 100746 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-29 18:58:00 +0000 (Fri, 29 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-13 11:16:30 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft PowerPoint 2016 Multiple RCE Vulnerabilities (KB4011041)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011041" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an error in
  Microsoft Office because it fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the context
  of the current user." );
	script_tag( name: "affected", value: "Microsoft PowerPoint 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011041" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/PowerPnt/Version", "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011041" );
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
offPath = path + "\\Microsoft Office\\OFFICE16";
exeVer = fetch_file_version( sysPath: offPath, file_name: "ppcore.dll" );
if(!exeVer){
	exit( 0 );
}
if(IsMatchRegexp( exeVer, "^16\\." ) && version_is_less( version: exeVer, test_version: "16.0.4588.1000" )){
	report = "File checked:     " + offPath + "\\ppcore.dll" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + "16.0 - 16.0.4588.0999" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

