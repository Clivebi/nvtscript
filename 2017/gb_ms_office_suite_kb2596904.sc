if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810774" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_cve_id( "CVE-2017-0281" );
	script_bugtraq_id( 98101 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-10 09:44:11 +0530 (Wed, 10 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Suite Remote Code Execution Vulnerability (KB2596904)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office Suite according to KB2596904." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist in Microsoft Office software
  when the software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user on an
  affected system." );
	script_tag( name: "affected", value: "Microsoft Office 2007 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/2596904" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0281" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
officeVer = fetch_file_version( sysPath: sysPath, file_name: "riched20.dll" );
if(!officeVer){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^12\\." )){
	if(version_in_range( version: officeVer, test_version: "12.0", test_version2: "12.0.6768.4999" )){
		report = "File checked:     " + sysPath + "\\riched20.dll" + "\n" + "File version:     " + officeVer + "\n" + "Vulnerable range: " + "12.0 - 12.0.6768.4999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

