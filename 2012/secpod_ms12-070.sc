if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902689" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-2552" );
	script_bugtraq_id( 55783 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-10-10 09:46:39 +0530 (Wed, 10 Oct 2012)" );
	script_name( "Microsoft SQL Server Report Manager Cross Site Scripting Vulnerability (2754849)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2754849" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1027623" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-070" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft SQL Server 2012

  - Microsoft SQL Server 2005 Service Pack 4 and prior

  - Microsoft SQL Server 2008 Service Pack 2 and prior

  - Microsoft SQL Server 2008 Service Pack 3 and prior

  - Microsoft SQL Server 2000 Reporting Services Service Pack 2" );
	script_tag( name: "insight", value: "An error exists in the SQL Server Reporting Services (SSRS), which can be
  exploited to insert client-side script code." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host has important security update missing according to
  Microsoft Bulletin MS12-070." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\Reporting Services\\Version";
if(registry_key_exists( key: key )){
	exeVer = registry_get_sz( key: key, item: "Version" );
	if(exeVer){
		if(version_is_less( version: exeVer, test_version: "8.0.1077.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
key = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\Services\\Report Server";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\";
if(registry_key_exists( key: key )){
	for item in registry_enum_keys( key: key ) {
		sysPath = registry_get_sz( key: key + item + "\\Tools\\Setup", item: "SQLPath" );
		if(ContainsString( sysPath, "Microsoft SQL Server" )){
			sysVer = fetch_file_version( sysPath: sysPath, file_name: "Binn\\VSShell\\Common7\\IDE\\Microsoft.reportingservices.diagnostics.dll" );
			if(sysVer){
				if(version_in_range( version: sysVer, test_version: "9.0.5000", test_version2: "9.0.5068" ) || version_in_range( version: sysVer, test_version: "9.0.5200", test_version2: "9.0.5323" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

