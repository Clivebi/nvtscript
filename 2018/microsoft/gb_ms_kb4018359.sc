if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812857" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-0950" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-11 08:50:08 +0530 (Wed, 11 Apr 2018)" );
	script_name( "Microsoft Word 2010 Service Pack 2 Information Disclosure Vulnerability (KB4018359)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4018359" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Office rendering Rich
  Text Format (RTF) email messages containing OLE objects when a message is opened
  or previewed." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to automatically initiate SMB session and to brute-force attack and disclose
  the hash password." );
	script_tag( name: "affected", value: "Microsoft Word 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4018359" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(IsMatchRegexp( exeVer, "^(14\\.)" ) && version_is_less( version: exeVer, test_version: "14.0.7197.5000" )){
	report = "File checked: " + exePath + "winword.exe" + "\n" + "File version: " + exeVer + "\n" + "Vulnerable range: 14.0 - 14.0.7197.4999" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

