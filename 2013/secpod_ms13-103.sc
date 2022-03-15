CPE = "cpe:/a:microsoft:visual_studio_team_foundation_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901227" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-5042" );
	script_bugtraq_id( 64093 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-11 10:49:08 +0530 (Wed, 11 Dec 2013)" );
	script_name( "Microsoft VS Team Foundation Server SignalR XSS Vulnerability (2905244)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to Microsoft
  Bulletin MS13-103." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Flaw is due ASP.NET SignalR improperly encodes user input before returning
  it to the user." );
	script_tag( name: "affected", value: "Microsoft Visual Studio Team Foundati on Microsoft Windows Server 2013." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary script
  code in a user's browser within the trust relationship between their
  browser and the server." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2903566" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-103" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_vs_team_foundation_server_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/VS/Team/Foundation/Server/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vs_tfs_ver = infos["version"];
if(!IsMatchRegexp( vs_tfs_ver, "^2013" )){
	exit( 0 );
}
vs_tfs_path = infos["location"];
if(vs_tfs_path && !ContainsString( vs_tfs_path, "Could not find the install location" )){
	signalr_file = "\\Application Tier\\Web Services\\bin\\Microsoft.AspNet.SignalR.Core.dll";
	vs_tfs_file_ver = fetch_file_version( sysPath: vs_tfs_path, file_name: signalr_file );
	if(vs_tfs_file_ver){
		if(version_is_less( version: vs_tfs_file_ver, test_version: "1.1.21022.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
exit( 99 );

