if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902992" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-2393", "CVE-2013-3776", "CVE-2013-3781" );
	script_bugtraq_id( 59129, 61234, 61232 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-08-14 13:28:33 +0530 (Wed, 14 Aug 2013)" );
	script_name( "MS Exchange Server Remote Code Execution Vulnerabilities (2876063)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
Microsoft Bulletin MS13-061." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "The flaws exist in the WebReady Document Viewing and Data Loss Prevention
features of Microsoft Exchange Server." );
	script_tag( name: "affected", value: "- Microsoft Exchange Server 2007 Service Pack 3

  - Microsoft Exchange Server 2010 Service Pack 2

  - Microsoft Exchange Server 2010 Service Pack 3" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to cause a denial of service
condition or run arbitrary code as LocalService on the affected Exchange
server." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2873746" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2874216" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2866475" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2874216" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-061" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
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
			if(version_is_less( version: exeVer, test_version: "8.3.327.1" ) || version_in_range( version: exeVer, test_version: "14.2", test_version2: "14.2.374" ) || version_in_range( version: exeVer, test_version: "14.3", test_version2: "14.3.158" ) || version_in_range( version: exeVer, test_version: "15.0.600", test_version2: "15.0.620.33" ) || version_in_range( version: exeVer, test_version: "15.0.700", test_version2: "15.0.712.27" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

