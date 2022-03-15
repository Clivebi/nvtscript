CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805991" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-2555", "CVE-2015-2558", "CVE-2015-6037" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-10-14 10:12:27 +0530 (Wed, 14 Oct 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS SharePoint Server Excel Services Multiple Vulnerabilities (3096440)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-110." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple memory corruption errors failing application to properly handle
  objects in memory.

  - Improper sanitization of specially crafted request." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to corrupt memory, execute arbitrary code on
  affected system and perform cross-site scripting attacks." );
	script_tag( name: "affected", value: "- Microsoft SharePoint Server 2007 Service Pack 3 Excel Services

  - Microsoft SharePoint Server 2010 Service Pack 2 Excel Services

  - Microsoft SharePoint Server 2013 Service Pack 1 Excel Services" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3054994" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085596" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085568" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085595" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/ms15-110.aspx" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/SharePoint/Server/Ver" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS15-110" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
shareVer = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( shareVer, "^12\\..*" )){
	path = path + "\\12.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6732.4999" )){
			report = "File checked:     " + path + "xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "12.0 - 12.0.6732.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^14\\..*" )){
	path = path + "\\14.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7159.4999" )){
			report = "File checked:     " + path + "xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7159.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	path = path + "\\15.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4763.999" )){
			report = "File checked:     " + path + "xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4763.999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

