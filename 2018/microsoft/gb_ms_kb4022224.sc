if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813562" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-8310" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-11 19:29:19 +0530 (Wed, 11 Jul 2018)" );
	script_name( "Microsoft Word 2013 Service Pack 1 Tampering Vulnerability (KB4022224)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4022224" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Microsoft
  Outlook does not properly handle specific attachment types when
  rendering HTML emails." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to bypass certain security restrictions, this may aid in
  launching further attacks." );
	script_tag( name: "affected", value: "Microsoft Word 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4022224" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
exeVer = get_kb_item( "SMB/Office/Word/Version" );
if(!exeVer){
	exit( 0 );
}
exePath = get_kb_item( "SMB/Office/Word/Install/Path" );
if(!exePath){
	exePath = "Unable to fetch the install path";
}
if(version_in_range( version: exeVer, test_version: "15.0", test_version2: "15.0.5049.0999" )){
	report = report_fixed_ver( file_checked: exePath + "winword.exe", file_version: exeVer, vulnerable_range: "15.0 - 15.0.5049.0999" );
	security_message( data: report );
	exit( 0 );
}

