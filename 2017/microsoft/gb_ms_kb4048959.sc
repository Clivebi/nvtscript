if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812139" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11869", "CVE-2017-11768", "CVE-2017-11788", "CVE-2017-11880", "CVE-2017-11791", "CVE-2017-11827", "CVE-2017-11834", "CVE-2017-11842", "CVE-2017-11843", "CVE-2017-11846", "CVE-2017-11847", "CVE-2017-11848", "CVE-2017-11849", "CVE-2017-11850", "CVE-2017-11851", "CVE-2017-11853", "CVE-2017-11855", "CVE-2017-11858", "CVE-2017-11831", "CVE-2017-11832" );
	script_bugtraq_id( 101742, 101705, 101711, 101755, 101715, 101703, 101725, 101719, 101740, 101741, 101729, 101709, 101762, 101738, 101763, 101764, 101751, 101716, 101721, 101726 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-30 19:07:00 +0000 (Thu, 30 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-15 10:19:08 +0530 (Wed, 15 Nov 2017)" );
	script_name( "Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4048959)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4048959" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This security update includes improvements and
  fixes.

  - Addressed issue where the virtual smart card doesn't assess the Trusted Platform
    Module (TPM) vulnerability correctly.

  - Addressed issue where applications based on the Microsoft JET Database Engine
    fail when creating or opening Microsoft Excel .xls files." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode, to cause a remote denial of service against
  a system. Also could obtain information to further compromise the user's system." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2012." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4048959" );
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
fileVer = fetch_file_version( sysPath: sysPath, file_name: "Mshtml.dll" );
if(!fileVer){
	exit( 0 );
}
if(version_is_less( version: fileVer, test_version: "10.0.9200.22297" )){
	report = report_fixed_ver( file_checked: sysPath + "\\Mshtml.dll", file_version: fileVer, vulnerable_range: "Less than 10.0.9200.22297" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

