if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812334" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11885", "CVE-2017-11907", "CVE-2017-11910", "CVE-2017-11912", "CVE-2017-11886", "CVE-2017-11887", "CVE-2017-11888", "CVE-2017-11889", "CVE-2017-11890", "CVE-2017-11894", "CVE-2017-11895", "CVE-2017-11899", "CVE-2017-11901", "CVE-2017-11903", "CVE-2017-11906", "CVE-2017-11913", "CVE-2017-11918", "CVE-2017-11919", "CVE-2017-11927", "CVE-2017-11930" );
	script_bugtraq_id( 102055, 102045, 102086, 102092, 102062, 102063, 102065, 102080, 102082, 102053, 102054, 102077, 102046, 102047, 102078, 102091, 102089, 102093, 102095, 102058 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 15:18:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "creation_date", value: "2017-12-13 10:08:48 +0530 (Wed, 13 Dec 2017)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4053581)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4053581" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in RPC if the server has Routing and Remote Access enabled.

  - An error when Internet Explorer improperly accesses objects in memory.

  - An error when Internet Explorer improperly handles objects in memory.

  - An error when the Windows its:// protocol handler unnecessarily sends traffic
    to a remote site in order to determine the zone of a provided URL.

  - An error when Microsoft Edge improperly accesses objects in memory.

  - An error in the way that the scripting engine handles objects in memory in
    Microsoft Edge.

  - An error in the way the scripting engine handles objects in memory in Microsoft
    browsers.

  - A security feature bypass exists when Device Guard incorrectly validates an
    untrusted file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code, gain the same user rights as the current user, obtain
  sensitive information to further compromise the user's system, a brute-force
  to disclose the NTLM hash password and make an unsigned file appear to be signed." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 for x64-based Systems

  - Microsoft Windows 10 for 32-bit Systems" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4053581" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(version_in_range( version: edgeVer, test_version: "11.0.10240.0", test_version2: "11.0.10240.17708" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Edgehtml.dll", file_version: edgeVer, vulnerable_range: "11.0.10240.0 - 11.0.10240.17708" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

