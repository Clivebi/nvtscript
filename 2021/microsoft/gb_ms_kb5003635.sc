if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818319" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-1675", "CVE-2021-26414", "CVE-2021-31199", "CVE-2021-31201", "CVE-2021-31951", "CVE-2021-31952", "CVE-2021-31954", "CVE-2021-31955", "CVE-2021-31956", "CVE-2021-31958", "CVE-2021-31959", "CVE-2021-31962", "CVE-2021-31968", "CVE-2021-31969", "CVE-2021-31970", "CVE-2021-31971", "CVE-2021-31972", "CVE-2021-31973", "CVE-2021-31974", "CVE-2021-31975", "CVE-2021-31976", "CVE-2021-31977", "CVE-2021-33739", "CVE-2021-33742" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-07 13:46:00 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 07:47:40 +0530 (Thu, 10 Jun 2021)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB5003635)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB5003635" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Server for NFS.

  - An error in HTML Platform.

  - An error in Scripting Engine.

  For more information about the vulnerabilities refer to Reference links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to perform remote code execution, gain access to potentially sensitive data,
  conduct DoS, bypass security features and elevate privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/topic/june-8-2021-kb5003635-os-build-18363-1621-2cc248e5-ca5f-4f51-bce4-004d6863e4cd" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
dllPath = smb_get_system32root();
if(!dllPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: dllPath, file_name: "mshtml.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_in_range( version: fileVer, test_version: "11.0.18362.0", test_version2: "11.0.18362.1620" )){
	report = report_fixed_ver( file_checked: dllPath + "\\mshtml.dll", file_version: fileVer, vulnerable_range: "11.0.18362.0 - 11.0.18362.1620" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );
