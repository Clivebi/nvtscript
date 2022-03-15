if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806660" );
	script_version( "2020-05-14T13:01:46+0000" );
	script_cve_id( "CVE-2016-0011", "CVE-2015-6117" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-14 13:01:46 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2016-01-13 12:19:11 +0530 (Wed, 13 Jan 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS SharePoint Server and Foundation Multiple Vulnerabilities (3124585)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-004." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to improper Access
  Control Policy (ACP) configuration settings." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform elevated privilege
  actions on the target." );
	script_tag( name: "affected", value: "- Microsoft SharePoint Server 2013 Service Pack 1 and

  - Microsoft SharePoint Foundation 2013 Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114503" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-004" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/SharePoint/Server_or_Foundation_or_Services/Installed" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
cpe_list = make_list( "cpe:/a:microsoft:sharepoint_server",
	 "cpe:/a:microsoft:sharepoint_foundation" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^15\\." )){
	check_path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(check_path){
		check_path += "\\microsoft shared\\SERVER15\\Server Setup Controller";
		check_file = "Wsssetup.dll";
		dllVer = fetch_file_version( sysPath: check_path, file_name: check_file );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4787.999" )){
				report = report_fixed_ver( file_checked: check_path + "\\" + check_file, file_version: dllVer, vulnerable_range: "15.0 - 15.0.4787.999", install_path: path );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

