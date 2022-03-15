CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804536" );
	script_version( "2020-11-12T08:54:04+0000" );
	script_cve_id( "CVE-2014-1761" );
	script_bugtraq_id( 66385 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-12 08:54:04 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-04-09 10:57:40 +0530 (Wed, 09 Apr 2014)" );
	script_name( "Microsoft SharePoint Server WAS Memory Corruption Vulnerability (2949660)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
Microsoft Bulletin MS14-017." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to the way that Microsoft Word parses specially crafted files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute the arbitrary
code and take complete control of the affected system." );
	script_tag( name: "affected", value: "- Microsoft SharePoint Server 2010 Word Automation Services

  - Microsoft SharePoint Server 2013 Word Automation Services" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2878220" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/2863907" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-017" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows : Microsoft Bulletins" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
		if(version_in_range( version: dllVer2, test_version: "14.0", test_version2: "14.0.7121.5003" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	dllVer2 = fetch_file_version( sysPath: path, file_name: "\\15.0\\WebServices\\ConversionServices\\sword.dll" );
	if(dllVer2){
		if(version_in_range( version: dllVer2, test_version: "15.0", test_version2: "15.0.4605.1000" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
exit( 99 );

