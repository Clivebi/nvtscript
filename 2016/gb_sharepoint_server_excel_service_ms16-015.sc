CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807305" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-0054" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:10:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-02-10 11:07:49 +0530 (Wed, 10 Feb 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS SharePoint Server Excel Services Remote Code Execution Vulnerability (3134226)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-015." );
	script_tag( name: "vuldetect", value: "Gets the vulnerable file version and checks if the
  appropriate patch is applied or not." );
	script_tag( name: "insight", value: "The flaw is due to memory corruption errors
  failing application to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to corrupt memory, execute arbitrary code on
  affected system and perform cross-site scripting attacks." );
	script_tag( name: "affected", value: "- Microsoft SharePoint Server 2007 Service Pack 3 Excel Services

  - Microsoft SharePoint Server 2010 Service Pack 2 Excel Services" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114335" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114432" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114401" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/ms16-015" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/SharePoint/Server/Ver" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-015" );
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
		if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6743.4999" )){
			report = "File checked:     " + path + "\\xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "12.0 - 12.0.6743.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	path = path + "\\15.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4797.0999" )){
			report = "File checked:     " + path + "\\xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4797.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^14\\..*" )){
	path = path + "\\14.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7166.4999" )){
			report = "File checked:     " + path + "\\xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7166.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

