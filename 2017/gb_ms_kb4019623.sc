if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811209" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_cve_id( "CVE-2017-0267", "CVE-2017-0268", "CVE-2017-0269", "CVE-2017-0270", "CVE-2017-0271", "CVE-2017-0272", "CVE-2017-0273", "CVE-2017-0274", "CVE-2017-0275", "CVE-2017-0276", "CVE-2017-0277", "CVE-2017-0278", "CVE-2017-0279", "CVE-2017-0280" );
	script_bugtraq_id( 98259, 98261, 98263, 98264, 98265, 98260, 98274, 98266, 98267, 98268, 98270, 98271, 98272, 98273 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-19 11:10:25 +0530 (Mon, 19 Jun 2017)" );
	script_name( "Microsoft Windows Multiple Vulnerabilities (KB4019623)" );
	script_tag( name: "summary", value: "This host is missing a critical/important
  security update according to Microsoft KB4019623" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to the error in
  the way Microsoft Server Message Block 1.0 (SMBv1) server handles certain
  requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause the affected system to stop responding until it is manually
  restarted. Also successful exploitation will allow attacker to get sensitive
  data and execute arbitrary code in context of current user." );
	script_tag( name: "affected", value: "Microsoft Windows 8 x86/x64." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4019623" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4025687" );
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
if(hotfix_check_sp( win8: 1, win8x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
if(!asVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\srv.sys" )){
	exit( 0 );
}
if(version_is_less( version: asVer, test_version: "6.2.9200.22137" )){
	report = "File checked:     " + sysPath + "\\drivers\\srv.sys" + "\n" + "File version:     " + asVer + "\n" + "Vulnerable range: " + "Less than 6.2.9200.22137" + "\n";
	security_message( data: report );
	exit( 0 );
}

