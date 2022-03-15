if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810775" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2017-0254" );
	script_bugtraq_id( 98101 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-10 10:38:22 +0530 (Wed, 10 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Viewer Remote Code Execution Vulnerability (KB3191909)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3191909" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as Office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Word Viewer 2007." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191909" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0254" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
wordviewPath = get_kb_item( "SMB/Office/WordView/Install/Path" );
if(!wordviewPath){
	wordviewPath = "Unable to fetch the install path";
}
if(wordviewVer){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8440" )){
		report = "File checked:     " + wordviewPath + "Wordview.exe" + "\n" + "File version:     " + wordviewVer + "\n" + "Vulnerable range: 11.0 - 11.0.8440\n";
		security_message( data: report );
		exit( 0 );
	}
}

