if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814742" );
	script_version( "2021-09-06T12:01:32+0000" );
	script_cve_id( "CVE-2019-0540" );
	script_bugtraq_id( 106863 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-13 10:55:46 +0530 (Wed, 13 Feb 2019)" );
	script_name( "Microsoft Office Word Viewer Security Feature Bypass Vulnerability (KB4462154)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4462154" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when Microsoft
  Office does not validate URLs." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to send a victim a specially crafted file, which could trick the victim into
  entering credentials." );
	script_tag( name: "affected", value: "Microsoft Office Word Viewer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4462154" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!os_arch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" );
	}
}
for key in key_list {
	propath = registry_get_sz( key: key, item: "CommonFilesDir" );
	if(propath){
		offPath = propath + "\\Microsoft Shared\\OFFICE11";
		exeVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
		if(exeVer && IsMatchRegexp( exeVer, "^(11\\.)" )){
			if(version_is_less( version: exeVer, test_version: "11.0.8453.0" )){
				report = report_fixed_ver( file_checked: offPath + "\\Mso.dll", file_version: exeVer, vulnerable_range: "11.0 - 11.0.8452" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );
