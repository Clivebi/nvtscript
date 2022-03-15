if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902969" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-1335" );
	script_bugtraq_id( 59759 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-05-15 09:30:40 +0530 (Wed, 15 May 2013)" );
	script_name( "Microsoft Office Wordview Remote Code Execution Vulnerability (2830399)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2817361" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-043" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "gb_smb_windows_detect.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word and RTF files." );
	script_tag( name: "affected", value: "Microsoft Word Viewer 2003." );
	script_tag( name: "insight", value: "The flaw is due to an error when parsing Rich Text Format (RTF) data related
  to the listoverridecount and can be exploited to corrupt memory." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-043." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(wordviewVer){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8401" )){
		report = report_fixed_ver( installed_version: wordviewVer, vulnerable_range: "11.0 - 11.0.8401" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

