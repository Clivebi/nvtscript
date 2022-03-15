if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807840" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-3233" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-06-15 11:19:38 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Excel Remote Code Execution Vulnerability (3163610)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-070." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft Excel improperly handles objects
  in memory while opening specially crafted Office file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Excel 2007 Service Pack 3 and prior

  - Microsoft Excel 2010 Service Pack 2 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3163610" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-070" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Excel/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
excelVer = get_kb_item( "SMB/Office/Excel/Version" );
excelPath = get_kb_item( "SMB/Office/Excel/Install/Path" );
if(!excelPath){
	excelPath = "Unable to fetch the install path";
}
if(!excelVer){
	exit( 0 );
}
if(IsMatchRegexp( excelVer, "^(12|14)\\..*" )){
	if( IsMatchRegexp( excelVer, "^12" ) ){
		Vulnerable_range = "12 - 12.0.6749.4999";
	}
	else {
		if(IsMatchRegexp( excelVer, "^14" )){
			Vulnerable_range = "14 - 14.0.7170.4999";
		}
	}
	if(version_in_range( version: excelVer, test_version: "12.0", test_version2: "12.0.6749.4999" ) || version_in_range( version: excelVer, test_version: "14.0", test_version2: "14.0.7170.4999" )){
		report = "File checked:     " + excelPath + "\\Excel.exe" + "\n" + "File version:     " + excelVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

