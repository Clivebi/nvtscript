CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809707" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053" );
	script_bugtraq_id( 82508, 82652, 82787 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-10-19 14:18:21 +0530 (Wed, 19 Oct 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft SharePoint Server WAS Multiple RCE Vulnerabilities (3134226)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-015." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are exists as office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft SharePoint Server 2013 Service Pack 1 Word Automation Services." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114481" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-015" );
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
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	dllVer2 = fetch_file_version( sysPath: path, file_name: "\\15.0\\WebServices\\ConversionServices\\sword.dll" );
	if(dllVer2){
		if(version_in_range( version: dllVer2, test_version: "15.0", test_version2: "15.0.4797.999" )){
			report = "File checked:     " + path + "\\15.0\\WebServices\\ConversionServices\\sword.dll" + "\n" + "File version:     " + dllVer2 + "\n" + "Vulnerable range: " + "15.0 - 15.0.4797.999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

