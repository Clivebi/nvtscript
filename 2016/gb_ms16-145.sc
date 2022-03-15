if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810237" );
	script_version( "2020-11-12T08:54:04+0000" );
	script_cve_id( "CVE-2016-7181", "CVE-2016-7206", "CVE-2016-7279", "CVE-2016-7280", "CVE-2016-7281", "CVE-2016-7282", "CVE-2016-7286", "CVE-2016-7287", "CVE-2016-7288", "CVE-2016-7296", "CVE-2016-7297" );
	script_bugtraq_id( 94735, 94737, 94719, 94750, 94723, 94724, 94748, 94722, 94749, 94738, 94751 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-12 08:54:04 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-12-14 08:20:30 +0530 (Wed, 14 Dec 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Edge Multiple Vulnerabilities (3204062)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-145." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The microsoft browsers fail to correctly apply same origin policy for
    scripts running inside Web Workers.

  - The multiple memory corruption vulnerabilities.

  - The microsoftb rowsers do not properly validate content under specific
    conditions." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to bypass security, access sensitive information, execute arbitrary code and
  take control of an affected system. An attacker could then install programs,
  view, change, or delete data, or create new accounts with full user rights." );
	script_tag( name: "affected", value: "- Microsoft Windows Server 2016

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3204062" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-145" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-145" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win10: 1, win10x64: 1, win2016: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
if(!egdeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" )){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1, win2016: 1 ) > 0){
	if( version_is_less( version: egdeVer, test_version: "11.0.10240.17202" ) ){
		Vulnerable_range = "Less than 11.0.10240.17202";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: egdeVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.712" ) ){
			Vulnerable_range = "11.0.10586.0 - 11.0.10586.712";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: egdeVer, test_version: "11.0.14393.0", test_version2: "11.0.14393.575" )){
				Vulnerable_range = "11.0.14393.0 - 11.0.14393.575";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\edgehtml.dll" + "\n" + "File version:     " + egdeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

