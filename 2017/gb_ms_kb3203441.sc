if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810941" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-8509" );
	script_bugtraq_id( 98812 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 12:22:56 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft Word Remote Code Execution Vulnerability (KB3203441)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3203441" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when the Office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  use a specially crafted file to perform actions in the security context of the
  current user." );
	script_tag( name: "affected", value: "Microsoft Word 2007 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3203441" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(IsMatchRegexp( exeVer, "^(12\\.)" ) && version_is_less( version: exeVer, test_version: "12.0.6770.5000" )){
	report = "File checked: " + exePath + "winword.exe" + "\n" + "File version: " + exeVer + "\n" + "Vulnerable range: 12.0 - 12.0.6770.4999 \n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

