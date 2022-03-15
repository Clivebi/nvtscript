if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811826" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2017-8742" );
	script_bugtraq_id( 100741 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-29 18:58:00 +0000 (Fri, 29 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-13 13:59:24 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft PowerPoint Viewer 2007 Remote Code Execution Vulnerability (KB3128030)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3128030" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Microsoft Office
  software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker who successfully exploited the vulnerability could run arbitrary
  code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft PowerPoint Viewer 2007." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3128030" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Office/PPView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
ppviewVer = get_kb_item( "SMB/Office/PPView/Version" );
if(!ppviewVer){
	exit( 0 );
}
ppviewPath = get_kb_item( "SMB/Office/PPView/FilePath" );
if(!ppviewPath){
	ppviewPath = "Unable to get installation path";
}
if(IsMatchRegexp( ppviewVer, "^(14\\.)" ) && version_is_less( version: ppviewVer, test_version: "14.0.7188.5000" )){
	report = "File checked:    " + ppviewPath + "\\pptview.exe" + "\n" + "File version:    " + ppviewVer + "\n" + "Vulnerable range: 14.0 - 14.0.7188.4999" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

