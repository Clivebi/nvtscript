if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807860" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-3280", "CVE-2016-3283", "CVE-2016-3282" );
	script_bugtraq_id( 91582, 91592, 91589 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-07-13 11:10:10 +0530 (Wed, 13 Jul 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Word Viewer Multiple RCE Vulnerabilities (3170008)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-088." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as Office software fails
  to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Word Viewer 2007." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115395" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3115393" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-088" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
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
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8430" )){
		report = "File checked:     " + wordviewPath + "Wordview.exe" + "\n" + "File version:     " + wordviewVer + "\n" + "Vulnerable range: 11.0 - 11.0.8430 \n";
		security_message( data: report );
	}
}
if(wordviewVer){
	InsPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(InsPath){
		offPath = InsPath + "\\Microsoft Shared\\" + "Office11";
		exeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
		if(exeVer && IsMatchRegexp( exeVer, "^11" )){
			if(version_in_range( version: exeVer, test_version: "11.0", test_version2: "11.0.8429" )){
				report = "File checked:     " + offPath + "\\mso.dll" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: 11.0 - 11.0.8429\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}

