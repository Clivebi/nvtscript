if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902919" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0017", "CVE-2012-0144", "CVE-2012-0145" );
	script_bugtraq_id( 51928, 51934, 51937 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-06-28 15:51:26 +0530 (Thu, 28 Jun 2012)" );
	script_name( "Microsoft SharePoint Privilege Elevation Vulnerabilities (2663841)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2553413" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2597124" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-011" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site." );
	script_tag( name: "affected", value: "- Microsoft SharePoint Server 2010 Service Pack 1 and prior

  - Microsoft SharePoint Foundation 2010 Service Pack 1 and prior" );
	script_tag( name: "insight", value: "Input passed to 'inplview.aspx', 'themeweb.aspx' and 'skey' parameter in
  'wizardlist.aspx' is not properly sanitised before being returned to the
  user. This can be exploited to execute arbitrary HTML and script code in a
  user's browser session in context of an affected site." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-011." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	spName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( spName, "Microsoft SharePoint Foundation 2010" ) || ContainsString( spName, "Microsoft SharePoint Server 2010" )){
		path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
		if(path){
			dllVer = fetch_file_version( sysPath: path, file_name: "Microsoft Shared\\Web Server Extensions\\14\\Bin\\ONFDA.dll" );
			if(dllVer){
				if(version_is_less( version: dllVer, test_version: "14.0.6106.5000" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
		spPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!spPath){
			exit( 0 );
		}
		spVer = fetch_file_version( sysPath: spPath, file_name: "14.0\\Bin\\Microsoft.office.server.native.dll" );
		if(!spVer){
			exit( 0 );
		}
		if(version_is_less( version: spVer, test_version: "14.0.6108.5000" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}

