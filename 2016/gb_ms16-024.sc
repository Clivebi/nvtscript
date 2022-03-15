if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807515" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-0102", "CVE-2016-0105", "CVE-2016-0109", "CVE-2016-0110", "CVE-2016-0111", "CVE-2016-0116", "CVE-2016-0123", "CVE-2016-0124", "CVE-2016-0125", "CVE-2016-0129", "CVE-2016-0130" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-09 09:58:26 +0530 (Wed, 09 Mar 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Edge Multiple Vulnerabilities (3142019)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-024." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - When Microsoft Edge improperly accesses objects in memory.

  - When Microsoft Edge improperly handles the referrer policy." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code, gain sensitive information and could take
  control of an affected system." );
	script_tag( name: "affected", value: "- Microsoft Edge on Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3142019" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-024" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_microsoft_edge_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Edge/Installed" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!dllVer){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	if( version_is_less( version: dllVer, test_version: "11.0.10240.16724" ) ){
		Vulnerable_range = "Less than 11.0.10240.16724";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: dllVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.161" )){
			Vulnerable_range = "11.0.10586.0 - 11.0.10586.161";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\edgehtml.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

