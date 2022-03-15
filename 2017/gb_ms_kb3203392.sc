if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810798" );
	script_version( "2021-09-17T12:01:50+0000" );
	script_cve_id( "CVE-2017-8510" );
	script_bugtraq_id( 98813 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 12:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 15:01:43 +0530 (Wed, 14 Jun 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Suite Remote Code Execution Vulnerability (KB3203392)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office Suite according to Microsoft KB3118310" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist in Microsoft Office software
  when the software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user on an
  affected system." );
	script_tag( name: "affected", value: "Microsoft Office 2013 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3203392/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3118310" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
offVer = get_kb_item( "MS/Office/Ver" );
if(!offVer){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(!path){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^15\\..*" )){
	filePath = path + "\\Microsoft Shared\\TextConv";
	fileVer = fetch_file_version( sysPath: filePath, file_name: "wpequ532.dll" );
	if(IsMatchRegexp( fileVer, "^2012" )){
		if(version_in_range( version: fileVer, test_version: "2012", test_version2: "2012.1500.4454.0999" )){
			report = "File checked:     " + filePath + "\\wpequ532.dll" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range: " + "2012 - 2012.1500.4454.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}

