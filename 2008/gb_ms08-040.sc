if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800105" );
	script_version( "2019-12-20T12:48:41+0000" );
	script_tag( name: "last_modification", value: "2019-12-20 12:48:41 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2008-10-14 16:26:50 +0200 (Tue, 14 Oct 2008)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-0085", "CVE-2008-0086", "CVE-2008-0106", "CVE-2008-0107" );
	script_bugtraq_id( 30119 );
	script_xref( name: "CB-A", value: "08-0110" );
	script_name( "MS SQL Server Elevation of Privilege Vulnerabilities (941203)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2022" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-040" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code,
  with a crafted SQL expression or Exposure of sensitive information or
  Privilege escalation." );
	script_tag( name: "affected", value: "- Microsoft SQL Server 2000 Service Pack 4

  - Microsoft SQL Server 2005 Service Pack 2

  - Microsoft SQL Server 2005 Edition Service Pack 2

  - Microsoft SQL Server 2005 Express Edition Service Pack 2

  - Microsoft SQL Server 2005 Express Edition with Advanced Services Service Pack 2" );
	script_tag( name: "insight", value: "The flaws are due to

  - error when initializing memory pages, while reallocating memory.

  - buffer overflow error in the convert function, while handling malformed
    input strings.

  - memory corruption error, while handling malformed data structures in
    on-disk files.

  - buffer overflow error, while processing malformed insert statements." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host has Microsoft SQL Server, which is prone to Privilege
  Escalation Vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
func Get_FileVersion( ver, path ){
	if(ver == "MS SQL Server 2005"){
		item = "SQLBinRoot";
		file = "\\sqlservr.exe";
		offset = 28000000;
	}
	if(ver == "MS SQL Server 2000"){
		item = "InstallLocation";
		file = "\\Binn\\sqlservr.exe";
		offset = 7800000;
	}
	sqlFile = registry_get_sz( key: path, item: item );
	if(!sqlFile){
		exit( 0 );
	}
	sqlFile += file;
	v = get_version( dllPath: sqlFile, string: "prod", offs: offset );
	return v;
}
if( registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft SQL Server 2005" ) ){
	msSqlSer = "MS SQL Server 2005";
}
else {
	if(registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft SQL Server 2000" )){
		msSqlSer = "MS SQL Server 2000";
	}
}
if(!msSqlSer){
	exit( 0 );
}
if( msSqlSer == "MS SQL Server 2005" ){
	reqSqlVer = "9.00.3068.00";
	insSqlVer = Get_FileVersion( ver: msSqlSer, path: "SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL.1\\Setup" );
}
else {
	if(msSqlSer == "MS SQL Server 2000"){
		reqSqlVer = "8.00.2050";
		insSqlVer = Get_FileVersion( ver: msSqlSer, path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft SQL Server 2000" );
	}
}
if(!insSqlVer){
	exit( 0 );
}
if(version_is_greater( version: reqSqlVer, test_version: insSqlVer )){
	report = report_fixed_ver( installed_version: insSqlVer, fixed_version: reqSqlVer );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

