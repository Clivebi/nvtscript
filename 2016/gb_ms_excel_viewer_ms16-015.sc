if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807304" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0054" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-02-10 10:47:16 +0530 (Wed, 10 Feb 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows Excel Viewer Remote Code Execution Vulnerability (3134226)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-015." );
	script_tag( name: "vuldetect", value: "Gets the vulnerable file version and checks if the
  appropriate patch is applied or not." );
	script_tag( name: "insight", value: "The flaw is due to Microsoft Excel improperly
  handles the loading of dynamic link library (DLL) files." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to execute remote code." );
	script_tag( name: "affected", value: "Microsoft Excel Viewer 2007 Service Pack 3 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114747" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-015" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/XLView/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelviewVer = get_kb_item( "SMB/Office/XLView/Version" );
if(IsMatchRegexp( excelviewVer, "^12\\..*" )){
	if(version_in_range( version: excelviewVer, test_version: "12.0", test_version2: "12.0.6743.4999" )){
		report = "File checked:     Xlview.exe" + "\n" + "File version:     " + excelviewVer + "\n" + "Vulnerable range: 12 - 12.0.6743.4999" + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

