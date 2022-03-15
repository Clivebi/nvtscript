if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.816881" );
	script_version( "2021-08-12T03:01:00+0000" );
	script_cve_id( "CVE-2020-0760" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 03:01:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-17 19:11:00 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-16 11:32:58 +0530 (Thu, 16 Apr 2020)" );
	script_name( "Microsoft Access Remote Code Execution Vulnerability (KB4462210)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4462210." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Microsoft Access software
  fails to loads arbitrary type libraries." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to take control of the affected system. An attacker could then install programs,
  view, change, or delete data or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Access 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4462210" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Office/Access/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
accVer = get_kb_item( "SMB/Office/Access/Version" );
if(!accVer){
	exit( 0 );
}
if(version_in_range( version: accVer, test_version: "15.0", test_version2: "15.0.5233.999" )){
	report = report_fixed_ver( file_checked: "msaccess.exe", file_version: accVer, vulnerable_range: "15.0 - 15.0.5233.999" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

