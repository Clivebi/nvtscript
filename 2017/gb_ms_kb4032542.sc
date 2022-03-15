if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811285" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_cve_id( "CVE-2017-8516" );
	script_bugtraq_id( 100041 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-14 18:02:00 +0000 (Mon, 14 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-08-09 15:23:11 +0530 (Wed, 09 Aug 2017)" );
	script_name( "Microsoft SQL Server 2014 Information Disclosure Vulnerability (KB4032542)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4032542." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in Microsoft
  SQL Server Analysis Services when it improperly enforces permissions." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to sensitive information and access to an affected SQL server
  database." );
	script_tag( name: "affected", value: "Microsoft SQL Server 2014 Service Pack 1 for x86/x64-based Systems (CU)." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4032542" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
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
			continue;
		}
		sql_path = sql_path - "Tools\\" + "Setup Bootstrap\\" + sql_ver_path + "\\" + arch;
		sysVer = fetch_file_version( sysPath: sql_path, file_name: "Microsoft.sqlserver.chainer.infrastructure.dll" );
		if(IsMatchRegexp( sysVer, "^12\\.0" )){
			if(version_in_range( version: sysVer, test_version: "12.0.4300.0", test_version2: "12.0.4521.0" )){
				report = "File checked:     " + sql_path + "\\microsoft.sqlserver.chainer.infrastructre.dll" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: 12.0.4300.0 - 12.0.4521.0\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

