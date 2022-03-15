if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817577" );
	script_version( "2021-08-25T14:01:09+0000" );
	script_cve_id( "CVE-2021-1648", "CVE-2021-1649", "CVE-2021-1650", "CVE-2021-1652", "CVE-2021-1653", "CVE-2021-1654", "CVE-2021-1655", "CVE-2021-1656", "CVE-2021-1657", "CVE-2021-1658", "CVE-2021-1659", "CVE-2021-1660", "CVE-2021-1661", "CVE-2021-1664", "CVE-2021-1665", "CVE-2021-1666", "CVE-2021-1667", "CVE-2021-1668", "CVE-2021-1671", "CVE-2021-1673", "CVE-2021-1674", "CVE-2021-1676", "CVE-2021-1678", "CVE-2021-1679", "CVE-2021-1688", "CVE-2021-1693", "CVE-2021-1694", "CVE-2021-1695", "CVE-2021-1696", "CVE-2021-1699", "CVE-2021-1700", "CVE-2021-1701", "CVE-2021-1702", "CVE-2021-1704", "CVE-2021-1706", "CVE-2021-1708", "CVE-2021-1709", "CVE-2021-1710" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 14:01:09 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 21:34:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-13 12:53:44 +0530 (Wed, 13 Jan 2021)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4598278)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4598278" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Microsoft splwow64.

  - An error in Active Template Library.

  - An error in Windows CSC Service.

  - An error in TPM Device Driver.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to perform remote code execution and elevate privilege." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2012." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4598278" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2012: 1 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "Localspl.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.2.9200.23255" )){
	report = report_fixed_ver( file_checked: dllPath + "\\Localspl.dll", file_version: fileVer, vulnerable_range: "Less than 6.2.9200.23255" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

