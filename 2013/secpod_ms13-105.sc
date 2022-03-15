if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903418" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-1330", "CVE-2013-5072", "CVE-2013-5763", "CVE-2013-5791" );
	script_bugtraq_id( 62221, 64085, 63741, 63076 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-11 10:09:38 +0530 (Wed, 11 Dec 2013)" );
	script_name( "MS Exchange Server Remote Code Execution Vulnerabilities (2915705)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to Microsoft
Bulletin MS13-105." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An unspecified error in the Outlook Web Access (OWA) service account.

  - Certain unspecified input is not properly sanitised before being returned
  to the user." );
	script_tag( name: "affected", value: "- Microsoft Exchange Server 2013

  - Microsoft Exchange Server 2007 Service Pack 3

  - Microsoft Exchange Server 2010 Service Pack 2

  - Microsoft Exchange Server 2010 Service Pack 3" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to run arbitrary code and
execute arbitrary HTML and script code in a user's browser session in context
of an affected site." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1029329" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2903911" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2903903" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2905616" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2880833" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1029459" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-105" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Exchange" ) && !registry_key_exists( key: "SOFTWARE\\Microsoft\\ExchangeServer" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for version in make_list( "Microsoft Exchange v14",
	 "Microsoft Exchange",
	 "Microsoft Exchange v15" ) {
	exchangePath = registry_get_sz( key: key + version, item: "InstallLocation" );
	if(exchangePath){
		exeVer = fetch_file_version( sysPath: exchangePath, file_name: "Bin\\ExSetup.exe" );
		if(exeVer){
			if(version_is_less( version: exeVer, test_version: "8.3.342.4" ) || version_in_range( version: exeVer, test_version: "14.2", test_version2: "14.2.390.2" ) || version_in_range( version: exeVer, test_version: "14.3", test_version2: "14.3.174" ) || version_in_range( version: exeVer, test_version: "15.0.770", test_version2: "15.0.775.40" ) || version_in_range( version: exeVer, test_version: "15.0.710", test_version2: "15.0.712.30" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

