if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812027" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11826" );
	script_bugtraq_id( 101219 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-12 02:29:00 +0000 (Tue, 12 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-10-11 11:11:30 +0530 (Wed, 11 Oct 2017)" );
	script_name( "Microsoft Office Word Viewer Remote Code Execution Vulnerability (KB4011236)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011236" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because Microsoft Office fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the context
  of the current user." );
	script_tag( name: "affected", value: "Microsoft Office Word Viewer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011236" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(!wordviewVer){
	exit( 0 );
}
wordviewPath = get_kb_item( "SMB/Office/WordView/Install/Path" );
if(!wordviewPath){
	wordviewPath = "Unable to fetch the install path";
}
if(IsMatchRegexp( wordviewVer, "^(11\\.)" ) && version_is_less( version: wordviewVer, test_version: "11.0.8444.0" )){
	report = "File checked:     " + wordviewPath + "wordview.exe" + "\n" + "File version:     " + wordviewVer + "\n" + "Vulnerable range: 11.0 - 11.0.8443" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );
