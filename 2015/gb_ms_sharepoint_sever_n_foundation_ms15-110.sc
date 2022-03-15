if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805993" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-2556", "CVE-2015-6039", "CVE-2015-6037" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-10-14 11:40:02 +0530 (Wed, 14 Oct 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MS SharePoint Server and Foundation Multiple Vulnerabilities (3096440)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-110." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the SharePoint InfoPath Forms Services improperly parses the
  Document Type Definition (DTD) of an XML file.

  - An error as SharePoint does not enforce the appropriate permission level
  for an application or user.

  - An error when an Office Web Apps Server does not properly sanitize a specially
  crafted request." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to perform cross-site scripting attacks on affected systems, bypass
  security restrictions and gain access to sensitive information." );
	script_tag( name: "affected", value: "- Microsoft SharePoint Server 2007 Service Pack 3

  - Microsoft SharePoint Server 2010 Service Pack 2

  - Microsoft SharePoint Server 2013 Service Pack 1 and

  - Microsoft SharePoint Foundation 2013 Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085567" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3085582" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/ms15-110.aspx" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2553405" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/2596670" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( vers, "^15\\." ) ){
	check_path = path + "15.0\\Bin";
	check_file = "Microsoft.office.server.conversions.launcher.exe";
	dllVer = fetch_file_version( sysPath: check_path, file_name: check_file );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4569.999" )){
			report = report_fixed_ver( file_checked: check_path + "\\" + check_file, file_version: dllVer, vulnerable_range: "15.0 - 15.0.4569.999", install_path: path );
			security_message( port: 0, data: report );
		}
	}
}
else {
	if( IsMatchRegexp( vers, "^15\\." ) ){
		check_path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
		if(check_path){
			check_path += "\\microsoft shared\\SERVER15\\Server Setup Controller";
			check_file = "Wsssetup.dll";
			dllVer = fetch_file_version( sysPath: check_path, file_name: check_file );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4763.999" )){
					report = report_fixed_ver( file_checked: check_path + "\\" + check_file, file_version: dllVer, vulnerable_range: "15.0 - 15.0.4763.999", install_path: path );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
	}
	else {
		if( IsMatchRegexp( vers, "^14\\." ) ){
			ckeck_path = path + "14.0\\Bin";
			check_file = "microsoft.office.infopath.server.dll";
			dllVer = fetch_file_version( sysPath: check_path, file_name: check_file );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7159.4999" )){
					report = report_fixed_ver( file_checked: check_path + "\\" + check_file, file_version: dllVer, vulnerable_range: "14.0 - 14.0.7159.4999", install_path: path );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
		else {
			if(IsMatchRegexp( vers, "^12\\." )){
				check_path = path + "12.0\\Bin";
				check_file = "microsoft.office.infopath.server.dll";
				dllVer = fetch_file_version( sysPath: check_path, file_name: check_file );
				if(dllVer){
					if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6732.4999" )){
						report = report_fixed_ver( file_checked: check_path + "\\" + check_file, file_version: dllVer, vulnerable_range: "12.0 - 12.0.6732.4999", install_path: path );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
			}
		}
	}
}
exit( 99 );

