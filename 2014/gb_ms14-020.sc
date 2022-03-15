if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804422" );
	script_version( "2019-12-20T12:48:41+0000" );
	script_cve_id( "CVE-2014-1759" );
	script_bugtraq_id( 66622 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 12:48:41 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-04-09 07:45:13 +0530 (Wed, 09 Apr 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft Office Publisher Remote Code Execution Vulnerability (2950145)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
  Bulletin MS14-020." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error within pubconv.dll. This can be exploited to
  corrupt memory and cause an invalid value to be dereferenced as a pointer via a specially crafted Publisher file." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  features." );
	script_tag( name: "affected", value: "- Microsoft Publisher 2003 Service Pack 3 and prior

  - Microsoft Publisher 2007 Service Pack 3 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2878299" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2817565" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-020" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "gb_smb_windows_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/Office/Publisher/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
offVer = get_kb_item( "SMB/Office/Publisher/Version" );
if(offVer && IsMatchRegexp( offVer, "^1[12]\\." )){
	pubFile = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\MSPUB.EXE", item: "Path" );
	if(pubFile){
		pubVer = fetch_file_version( sysPath: pubFile, file_name: "\\Pubconv.dll" );
		if(pubVer){
			if(version_in_range( version: pubVer, test_version: "11.0", test_version2: "11.0.8409" ) || version_in_range( version: pubVer, test_version: "12.0", test_version2: "12.0.6694.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

