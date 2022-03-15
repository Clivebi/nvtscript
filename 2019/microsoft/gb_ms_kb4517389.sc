if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815493" );
	script_version( "2021-09-06T12:01:32+0000" );
	script_cve_id( "CVE-2019-0608", "CVE-2019-1060", "CVE-2019-1166", "CVE-2019-1192", "CVE-2019-1238", "CVE-2019-1307", "CVE-2019-1308", "CVE-2019-1311", "CVE-2019-1315", "CVE-2019-1316", "CVE-2019-1317", "CVE-2019-1318", "CVE-2019-1319", "CVE-2019-1320", "CVE-2019-1321", "CVE-2019-1322", "CVE-2019-1323", "CVE-2019-1325", "CVE-2019-1326", "CVE-2019-1333", "CVE-2019-1334", "CVE-2019-1335", "CVE-2019-1336", "CVE-2019-1337", "CVE-2019-1339", "CVE-2019-1340", "CVE-2019-1341", "CVE-2019-1342", "CVE-2019-1343", "CVE-2019-1344", "CVE-2019-1345", "CVE-2019-1346", "CVE-2019-1347", "CVE-2019-1356", "CVE-2019-1357", "CVE-2019-1358", "CVE-2019-1359", "CVE-2019-1365", "CVE-2019-1366", "CVE-2019-1367", "CVE-2019-1368", "CVE-2019-1371" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-11 19:57:00 +0000 (Fri, 11 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-10-09 10:13:33 +0530 (Wed, 09 Oct 2019)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4517389)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4517389" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle
    attacker is able to successfully bypass the NTLM MIC (Message Integrity Check)
    protection.

  - Chakra scripting engine improperly handles objects in memory in Microsoft Edge.

  - A spoofing vulnerability exists when Transport Layer Security (TLS) accesses
    non Extended Master Secret (EMS) sessions.

  - Microsoft Windows Update Client does not properly handle privileges.

  - Windows Error Reporting manager improperly handles process crashes.

  - Microsoft Browsers does not properly parse HTTP content.

  - Scripting engine handles objects in memory in Internet Explorer.

  Please see the references for more information about the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code on the client machine, bypass security restrictions,
  elevate privileges and read privileged data across trust boundaries, create a
  denial of service condition and conduct spoofing attack." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1903 for 32-bit Systems

  - Microsoft Windows 10 Version 1903 for x64-based Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4517389" );
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
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "Schannel.dll" );
if(!dllVer){
	exit( 0 );
}
if(version_in_range( version: dllVer, test_version: "10.0.18362.0", test_version2: "10.0.18362.417" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Schannel.dll", file_version: dllVer, vulnerable_range: "10.0.18362.0 - 10.0.18362.417" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

