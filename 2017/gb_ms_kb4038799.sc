if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811823" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-0161", "CVE-2017-8719", "CVE-2017-8720", "CVE-2017-8728", "CVE-2017-8733", "CVE-2017-8675", "CVE-2017-8676", "CVE-2017-8737", "CVE-2017-8741", "CVE-2017-8678", "CVE-2017-8679", "CVE-2017-8680", "CVE-2017-8749", "CVE-2017-8681", "CVE-2017-8682", "CVE-2017-8683", "CVE-2017-8684", "CVE-2017-8686", "CVE-2017-8687", "CVE-2017-8688", "CVE-2017-8692", "CVE-2017-8695", "CVE-2017-8699", "CVE-2017-8707", "CVE-2017-8708", "CVE-2017-8709", "CVE-2017-8713", "CVE-2017-8714", "CVE-2017-8677", "CVE-2017-8747" );
	script_bugtraq_id( 100728, 100739, 100737, 100752, 100755, 100749, 100764, 100769, 100720, 100722, 100770, 100727, 100772, 100781, 100782, 100730, 100736, 100756, 100762, 100773, 100783, 100790, 100791, 100792, 100796, 100767, 100765 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-10 19:58:00 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2017-09-13 12:55:59 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4038799)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4038799" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist. Please see the references for more information." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to execute arbitrary code, escalate privileges and obtain sensitive
  information." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2012." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4038799" );
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
if(hotfix_check_sp( win2012: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
fileVer = fetch_file_version( sysPath: sysPath, file_name: "glcndfilter.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "6.2.9200.22257" )){
	report = "File checked:     " + sysPath + "\\glcndfilter.dll" + "\n" + "File version:     " + fileVer + "\n" + "Vulnerable range:  Less than 6.2.9200.22257\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

