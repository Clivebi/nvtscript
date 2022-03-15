if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808225" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-3198", "CVE-2016-3199", "CVE-2016-3201", "CVE-2016-3202", "CVE-2016-3203", "CVE-2016-3214", "CVE-2016-3215", "CVE-2016-3222" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-06-15 08:30:23 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Edge Multiple Vulnerabilities (3163656)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-068." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - when the Edge Content Security Policy (CSP) fails to properly validate
    certain specially crafted documents.

  - when improperly handle objects in memory in Microsoft Edge.

  - when a user opens a specially crafted .pdf file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to trick a user into loading a page containing malicious content,
  to trick the user into opening the .pdf file and read information in the context
  of the current user and to execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3163018" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3163017" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-068" );
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
edgedllVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!edgedllVer){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	if( version_is_less( version: edgedllVer, test_version: "11.0.10240.16942" ) ){
		Vulnerable_range = "Less than 11.0.10240.16942";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: edgedllVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.419" )){
			Vulnerable_range = "11.0.10586.0 - 11.0.10586.419";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\edgehtml.dll" + "\n" + "File version:     " + edgedllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

