if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811863" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11826" );
	script_bugtraq_id( 101219 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-12 02:29:00 +0000 (Tue, 12 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-10-11 10:16:39 +0530 (Wed, 11 Oct 2017)" );
	script_name( "Microsoft SharePoint Enterprise Server 2016 Remote Code Execution Vulnerability (KB4011217)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011217" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Microsoft Office
  software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker who successfully exploited the vulnerability to run arbitrary
  code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft SharePoint Enterprise Server 2016." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011217" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:sharepoint_server", exit_no_version: TRUE )){
	exit( 0 );
}
shareVer = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( shareVer, "^16\\..*" )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(path){
		path = path + "\\microsoft shared\\Web Server Extensions\\16\\BIN";
		dllVer = fetch_file_version( sysPath: path, file_name: "Onetutil.dll" );
		if(dllVer && version_in_range( version: dllVer, test_version: "16.0", test_version2: "16.0.4600.0999" )){
			report = "File checked:     " + path + "\\Onetutil.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: 16.0 - 16.0.4600.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

