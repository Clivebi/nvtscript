if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815507" );
	script_version( "2021-09-06T12:01:32+0000" );
	script_cve_id( "CVE-2019-1068" );
	script_bugtraq_id( 108954 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-10 12:42:11 +0530 (Wed, 10 Jul 2019)" );
	script_name( "Microsoft SQL Server Remote Code Execution Vulnerability (KB4505224)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4505224" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  Microsoft SQL Server Database Engine. It incorrectly handles processing
  of internal functions." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code within the context of the SQL Server Database
  Engine service account. Failed exploit attempts may result in a
  denial-of-service condition." );
	script_tag( name: "affected", value: "Microsoft SQL Server 2017 GDR." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4505224" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!ContainsString( os_arch, "x64" )){
	exit( 0 );
}
ms_sql_key = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\";
if(!registry_key_exists( key: ms_sql_key )){
	exit( 0 );
}
for item in registry_enum_keys( key: ms_sql_key ) {
	sql_path = registry_get_sz( key: ms_sql_key + item + "\\Tools\\Setup", item: "SQLPath" );
	if(!sql_path){
		sql_path = registry_get_sz( key: ms_sql_key + item + "\\Tools\\ClientSetup", item: "SQLPath" );
		sql_ver = registry_get_sz( key: ms_sql_key + item + "\\Tools\\ClientSetup\\CurrentVersion", item: "CurrentVersion" );
	}
	if(!sql_ver){
		sql_ver = registry_get_sz( key: ms_sql_key + item + "\\Tools\\Setup", item: "Version" );
	}
	if(!sql_ver){
		continue;
	}
	if(ContainsString( sql_path, "Microsoft SQL Server" )){
		sql_ver_path = "";
		if( IsMatchRegexp( sql_ver, "^14\\.0" ) ){
			sql_ver_path = "SQL2017";
		}
		else {
			continue;
		}
		sql_path = sql_path - "Tools" + "Setup Bootstrap\\" + sql_ver_path + "\\" + os_arch;
		sysVer = fetch_file_version( sysPath: sql_path, file_name: "Microsoft.sqlserver.chainer.infrastructure.dll" );
		if(sysVer && IsMatchRegexp( sysVer, "^14\\.0" )){
			if(version_in_range( version: sysVer, test_version: "14.0.1000.169", test_version2: "14.0.2027.1" )){
				report = report_fixed_ver( file_checked: sql_path + "\\microsoft.sqlserver.chainer.infrastructure.dll", file_version: sysVer, vulnerable_range: "14.0.1000.169 - 14.0.2027.1" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

