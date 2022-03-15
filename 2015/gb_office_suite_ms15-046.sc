if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805180" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2015-1682", "CVE-2015-1683" );
	script_bugtraq_id( 74481, 74484 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-05-13 14:51:10 +0530 (Wed, 13 May 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Suite Remote Code Execution Vulnerability (3057181)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-046." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as user supplied input is
  not properly validated." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 2 and prior

  - Microsoft Office 2013 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2965282" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2965311" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2999412" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2965242" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2975808" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-046" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_office_detection_900025.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^12\\." )){
	InsPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(InsPath){
		offPath = InsPath + "\\Microsoft Shared\\Office12";
		exeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
		if(exeVer){
			if(version_in_range( version: exeVer, test_version: "12.0", test_version2: "12.0.6721.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(officeVer && IsMatchRegexp( officeVer, "^14\\." )){
	comPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Office\\14.0\\Access\\InstallRoot", item: "Path" );
	if(comPath){
		ortVer = fetch_file_version( sysPath: comPath, file_name: "Oart.dll" );
		ortconVer = fetch_file_version( sysPath: comPath, file_name: "Oartconv.dll" );
		if(!isnull( ortVer ) || !isnull( ortconVer )){
			if(version_in_range( version: ortVer, test_version: "14.0", test_version2: "14.0.7149.4999" ) || version_in_range( version: ortconVer, test_version: "14.0", test_version2: "14.0.7149.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(officeVer && IsMatchRegexp( officeVer, "^15\\." )){
	comPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Office\\15.0\\Access\\InstallRoot", item: "Path" );
	if(comPath){
		ortVer = fetch_file_version( sysPath: comPath, file_name: "Oart.dll" );
		if(ortVer){
			if(version_in_range( version: ortVer, test_version: "15.0", test_version2: "15.0.4719.999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

