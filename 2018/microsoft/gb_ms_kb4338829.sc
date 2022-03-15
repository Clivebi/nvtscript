if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813649" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8282", "CVE-2018-8284", "CVE-2018-0949", "CVE-2018-8125", "CVE-2018-8202", "CVE-2018-8206", "CVE-2018-8222", "CVE-2018-8242", "CVE-2018-8280", "CVE-2018-8287", "CVE-2018-8288", "CVE-2018-8290", "CVE-2018-8291", "CVE-2018-8296", "CVE-2018-8304", "CVE-2018-8307", "CVE-2018-8308", "CVE-2018-8309", "CVE-2018-8313", "CVE-2018-8314", "CVE-2018-8356", "CVE-2018-3665" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-11 11:15:15 +0530 (Wed, 11 Jul 2018)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4338829)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4338829" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to errors,

  - When Windows improperly handles File Transfer Protocol (FTP) connections.

  - When Chakra scripting engine improperly handles objects in memory in
    browsers.

  - When Windows Kernel API improperly enforces permissions.

  - when Windows improperly handles objects in memory.

  - When the Windows kernel fails to properly handle objects in memory.

  - When Microsoft WordPad improperly handles embedded OLE objects.

  - When the scripting engine improperly handles objects in memory in
    Microsoft browsers.

  - When Windows fails a check, allowing a sandbox escape.

  - A security feature bypass vulnerability exists in Device Guard.

  - When Microsoft Internet Explorer improperly handles requests involving
    UNC resources.

  - When the Windows kernel-mode driver fails to properly handle objects in memory.

  - When Microsoft Edge improperly accesses objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause a target system to stop responding, elevate their privilege level,
  run arbitrary code, bypass security, disclose sensitive information and also
  take control of an affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4338829" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!edgeVer){
	exit( 0 );
}
if(version_in_range( version: edgeVer, test_version: "11.0.10240.0", test_version2: "11.0.10240.17913" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Edgehtml.dll", file_version: edgeVer, vulnerable_range: "11.0.10240.0 - 11.0.10240.17913" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

