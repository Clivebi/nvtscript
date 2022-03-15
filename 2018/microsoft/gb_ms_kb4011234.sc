if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813032" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-0903" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-14 09:45:51 +0530 (Wed, 14 Mar 2018)" );
	script_name( "Microsoft Access Remote Code Execution Vulnerability (KB4011234)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011234" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Microsoft Access software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user. If the current user
  is logged on with administrative user rights, an attacker could take control
  of the affected system." );
	script_tag( name: "affected", value: "Microsoft Access 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011234" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_in_range( version: accVer, test_version: "15.0", test_version2: "15.0.5013.999" )){
	report = report_fixed_ver( file_checked: "msaccess.exe", file_version: accVer, vulnerable_range: "15.0 - 15.0.5013.999" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

