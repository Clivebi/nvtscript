CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903332" );
	script_version( "2021-08-04T10:08:11+0000" );
	script_cve_id( "CVE-2013-5059" );
	script_bugtraq_id( 64081 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-01-09 12:53:16 +0530 (Thu, 09 Jan 2014)" );
	script_name( "Microsoft SharePoint Business Productivity Server RCE Vulnerability (2904244)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
  Bulletin MS13-100." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Flaws is due to some input sanitisation errors related to SharePoint content" );
	script_tag( name: "affected", value: "- Microsoft Business Productivity Servers on

  - Microsoft SharePoint Server 2010 Service Pack 1

  - Microsoft SharePoint Server 2010 Service Pack 2

  - Microsoft SharePoint 2013" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code with
  the privileges of the W3WP service account." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-100" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_mandatory_keys( "MS/SharePoint/Server/Ver" );
	script_require_ports( 139, 445 );
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
	path = path + "\\14.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "ascalc.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7011.999" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	path = path + "\\15.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "ascalc.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4545.999" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
exit( 99 );

