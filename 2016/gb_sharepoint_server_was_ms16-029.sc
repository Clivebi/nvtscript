CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807893" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-0134" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-10-05 15:40:03 +0530 (Wed, 05 Oct 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft SharePoint Server WAS Remote Code Execution Vulnerability (3141806)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-029." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as Office software fails to properly
  handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft SharePoint Server 2010 Service Pack 2 Word Automation Services

  - Microsoft SharePoint Server 2013 Service Pack 1 Word Automation Services" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3114866" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3114814" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/ms16-029" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( shareVer, "^14\\..*" )){
	dllVer2 = fetch_file_version( sysPath: path, file_name: "\\14.0\\WebServices\\WordServer\\Core\\sword.dll" );
	if(dllVer2){
		if(version_in_range( version: dllVer2, test_version: "14.0", test_version2: "14.0.7167.4999" )){
			report = "File checked:     " + path + "\\14.0\\WebServices\\WordServer\\Core\\sword.dll" + "\n" + "File version:     " + dllVer2 + "\n" + "Vulnerable range: " + "14.0 - 14.0.7167.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	dllVer2 = fetch_file_version( sysPath: path, file_name: "\\15.0\\WebServices\\ConversionServices\\sword.dll" );
	if(dllVer2){
		if(version_in_range( version: dllVer2, test_version: "15.0", test_version2: "15.0.4805.999" )){
			report = "File checked:     " + path + "\\15.0\\WebServices\\ConversionServices\\sword.dll" + "\n" + "File version:     " + dllVer2 + "\n" + "Vulnerable range: " + "15.0 - 15.0.4805.999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

