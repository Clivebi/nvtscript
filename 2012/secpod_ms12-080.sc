if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902697" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-3214", "CVE-2012-3217", "CVE-2012-4791" );
	script_bugtraq_id( 55977, 55993, 56836 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-12-12 12:01:07 +0530 (Wed, 12 Dec 2012)" );
	script_name( "MS Exchange Server Remote Code Execution Vulnerabilities (2784126)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027669" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1027857" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-077" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to cause a denial of service
  condition or run arbitrary code as LocalService on the affected Exchange
  server." );
	script_tag( name: "affected", value: "- Microsoft Exchange Server 2007 Service Pack 3

  - Microsoft Exchange Server 2010 Service Pack 1

  - Microsoft Exchange Server 2010 Service Pack 2" );
	script_tag( name: "insight", value: "The flaws are due to

  - Error in the WebReady Document Viewing when used to preview a
    specially crafted file through Outlook Web Access.

  - Improper handling of RSS feeds rendering the Information Store service
    unresponsive until the process is forcibly terminated and corrupt the
    databases." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-080." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Exchange" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for version in make_list( "Microsoft Exchange v14",
	 "Microsoft Exchange" ) {
	key = key + version;
	exchangePath = registry_get_sz( key: key, item: "InstallLocation" );
	if(exchangePath){
		exeVer = fetch_file_version( sysPath: exchangePath, file_name: "Bin\\ExSetup.exe" );
		if(exeVer){
			if(version_is_less( version: exeVer, test_version: "8.3.297.2" ) || ( IsMatchRegexp( exeVer, "^(14.0|14.1)" ) && version_is_less( version: exeVer, test_version: "14.1.438.0" ) ) || version_in_range( version: exeVer, test_version: "14.2", test_version2: "14.2.328.9" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

