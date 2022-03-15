if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811667" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2017-8630" );
	script_bugtraq_id( 100732 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-21 16:10:00 +0000 (Thu, 21 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-13 09:18:23 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Office 2016 Remote Code Execution Vulnerability (KB3203474)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3203474" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  Microsoft Office software when it fails to properly handle objects in
  memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker who successfully exploited the vulnerability could use a specially
  crafted file to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3203474" );
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
if(IsMatchRegexp( officeVer, "^16\\." )){
	comPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Office\\16.0\\Access\\InstallRoot", item: "Path" );
	if(comPath){
		ortVer = fetch_file_version( sysPath: comPath, file_name: "Oart.dll" );
		if(ortVer){
			if(version_in_range( version: ortVer, test_version: "16", test_version2: "16.0.4588.0999" )){
				report = "File checked:     " + comPath + "\\Oart.dll" + "\n" + "File version:     " + ortVer + "\n" + "Vulnerable range:  16.0 - 16.0.4588.0999 \n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

