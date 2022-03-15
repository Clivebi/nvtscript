if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802080" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2014-1820", "CVE-2014-4061" );
	script_bugtraq_id( 69071, 69088 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2014-08-13 17:35:15 +0530 (Wed, 13 Aug 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft SQL Server Elevation of Privilege Vulnerability (2984340)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-044." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to:

  - SQL Master Data Services (MDS) does not properly encode output.

  - SQL Server processes an incorrectly formatted T-SQL query." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a Denial
  of Service or elevation of privilege." );
	script_tag( name: "affected", value: "- Microsoft SQL Server 2014 x64 Edition

  - Microsoft SQL Server 2012 x86/x64 Edition Service Pack 1 and prior

  - Microsoft SQL Server 2008 R2 x86/x64 Edition Service Pack 2 and prior

  - Microsoft SQL Server 2008 x86/x64 Edition Service Pack 3 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-044" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x64" ) ){
	arch = "x64";
}
else {
	if( ContainsString( os_arch, "x86" ) ){
		arch = "x86";
	}
	else {
		exit( 0 );
	}
}
ms_sql_key = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\";
if(!registry_key_exists( key: ms_sql_key )){
	exit( 0 );
}
for item in registry_enum_keys( key: ms_sql_key ) {
	sql_path = registry_get_sz( key: ms_sql_key + item + "\\Tools\\Setup", item: "SQLPath" );
	sql_ver = registry_get_sz( key: ms_sql_key + item + "\\Tools\\Setup", item: "Version" );
	if(!sql_ver){
		continue;
	}
	if(ContainsString( sql_path, "Microsoft SQL Server" )){
		sql_ver_path = "";
		if( IsMatchRegexp( sql_ver, "^12\\.0" ) ){
			sql_ver_path = "SQLServer2014";
		}
		else {
			if( IsMatchRegexp( sql_ver, "^11\\.0" ) ){
				sql_ver_path = "SQLServer2012";
			}
			else {
				if( IsMatchRegexp( sql_ver, "^10\\.50" ) ){
					sql_ver_path = "SQLServer2008R2";
				}
				else {
					if( IsMatchRegexp( sql_ver, "^10\\.0" ) ){
						sql_ver_path = "SQLServer2008";
					}
					else {
						continue;
					}
				}
			}
		}
		sql_path = sql_path - "Tools\\" + "Setup Bootstrap\\" + sql_ver_path + "\\" + arch;
		sysVer = fetch_file_version( sysPath: sql_path, file_name: "Microsoft.sqlserver.chainer.infrastructure.dll" );
		if(sysVer){
			if(IsMatchRegexp( sysVer, "^12\\.0" )){
				if(version_in_range( version: sysVer, test_version: "12.0.2000", test_version2: "12.0.2253" ) || version_in_range( version: sysVer, test_version: "12.0.2300", test_version2: "12.0.2380" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(IsMatchRegexp( sysVer, "^11\\.0" )){
				if(version_in_range( version: sysVer, test_version: "11.0.3000", test_version2: "11.0.3152" ) || version_in_range( version: sysVer, test_version: "11.0.3300", test_version2: "11.0.3459" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(IsMatchRegexp( sysVer, "^10\\.50" )){
				if(version_in_range( version: sysVer, test_version: "10.50.4000", test_version2: "10.50.4032" ) || version_in_range( version: sysVer, test_version: "10.50.4251", test_version2: "10.50.4320" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(IsMatchRegexp( sysVer, "^10\\.0" )){
				if(version_in_range( version: sysVer, test_version: "10.0.5500", test_version2: "10.0.5519" ) || version_in_range( version: sysVer, test_version: "10.0.5750", test_version2: "10.0.5868" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

