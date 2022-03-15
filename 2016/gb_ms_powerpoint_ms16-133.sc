if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809719" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-7230" );
	script_bugtraq_id( 94006 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-11-09 13:16:52 +0530 (Wed, 09 Nov 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office PowerPoint Remote Code Execution Vulnerability (3199168)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-133." );
	script_tag( name: "vuldetect", value: "Gets the vulnerable file version and checks if the
  appropriate patch is applied or not." );
	script_tag( name: "insight", value: "The flaw exists as Office software fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in
  user." );
	script_tag( name: "affected", value: "Microsoft PowerPoint 2010 Service Pack 2 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3118378" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-133" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Office/PowerPnt/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
pptVer = get_kb_item( "SMB/Office/PowerPnt/Version" );
if(!pptVer){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!path){
	exit( 0 );
}
offPath = path + "\\Microsoft Office\\OFFICE14";
exeVer = fetch_file_version( sysPath: offPath, file_name: "ppcore.dll" );
if(exeVer && IsMatchRegexp( exeVer, "^14.*" )){
	if(version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.0.7176.4999" )){
		report = "File checked:     " + offPath + "\\ppcore.dll" + "\n" + "File version:     " + exeVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7176.4999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

