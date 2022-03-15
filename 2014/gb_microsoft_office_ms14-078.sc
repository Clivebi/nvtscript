if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804883" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-4077" );
	script_bugtraq_id( 70944 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-11-13 15:00:11 +0530 (Thu, 13 Nov 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft Office IME (Japanese) Privilege Elevation Vulnerability (2992719)" );
	script_tag( name: "summary", value: "This host is missing a moderate security
  update according to Microsoft Bulletin MS14-078." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Error in 'IMJPDCT.EXE', which allow
  remote attackers to bypass a sandbox protection mechanism via a crafted PDF
  document. Aka 'Microsoft IME (Japanese) Elevation of Privilege Vulnerability'
  as exploited in the wild in 2014." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to bypass a sandbox protection mechanism via a crafted PDF document." );
	script_tag( name: "affected", value: "Microsoft Office 2007 Service Pack 3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2992719" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2889913" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-078" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
offVer = get_kb_item( "MS/Office/Ver" );
if(!offVer){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^12\\..*" )){
	key = "SOFTWARE\\Microsoft\\IMEJP\\12.0";
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
	path = registry_get_sz( key: key + "\\directories", item: "ModulePath" );
	if(!path){
		exit( 0 );
	}
	fileVer = fetch_file_version( sysPath: path, file_name: "Imjputyc.dll" );
	if(!fileVer){
		exit( 0 );
	}
	if(version_in_range( version: fileVer, test_version: "12.0", test_version2: "12.0.6652.4999" )){
		report = report_fixed_ver( installed_version: fileVer, vulnerable_range: "12.0 - 12.0.6652.4999", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

