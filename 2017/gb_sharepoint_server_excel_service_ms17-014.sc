CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810709" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2017-0006", "CVE-2017-0052", "CVE-2017-0027" );
	script_bugtraq_id( 96740, 96741, 96043 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-15 13:33:17 +0530 (Wed, 15 Mar 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS SharePoint Server Excel Services Multiple Vulnerabilities (4013241)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS17-014." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - Microsoft Office improperly handles input.

  - Microsoft Office software reads out of bound memory.

  - Microsoft Office software improperly handles the parsing of file formats." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and gain
  access to potentially sensitive information." );
	script_tag( name: "affected", value: "Excel Services on SharePoint Server 2013

  Microsoft SharePoint Server 2010 Excel Services

  Microsoft SharePoint Server 2007 Service Pack 3 Excel Services" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3178678" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3178685" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3172431" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms17-014" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/SharePoint/Server/Ver" );
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
		if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6765.4999" )){
			report = "File checked:     " + path + "\\xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "12.0 - 12.0.6765.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^14\\..*" )){
	path = path + "\\14.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7179.4999" )){
			report = "File checked:     " + path + "\\xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7179.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	path = path + "\\15.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4911.0999" )){
			report = "File checked:     " + path + "\\xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4911.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

