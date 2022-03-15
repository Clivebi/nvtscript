CPE = "cpe:/a:microsoft:sharepoint_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810714" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-0107" );
	script_bugtraq_id( 96748 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-15 15:39:46 +0530 (Wed, 15 Mar 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft SharePoint Foundation Cross Site Scripting Vulnerability (4013241)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS17-014." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Microsoft SharePoint does not properly
  sanitize a specially crafted web request to an affected SharePoint server." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to perform cross-site scripting attacks on affected systems and run script
  in the security context of the current user." );
	script_tag( name: "affected", value: "Microsoft SharePoint Foundation 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3172540" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS17-014" );
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
if(IsMatchRegexp( shareVer, "^15\\..*" )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(path){
		path = path + "\\microsoft shared\\Web Server Extensions\\15\\BIN";
		dllVer = fetch_file_version( sysPath: path, file_name: "Onetutil.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4911.0999" )){
				report = "File checked:     " + path + "\\Onetutil.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4911.0999" + "\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

