if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811228" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2017-8501" );
	script_bugtraq_id( 99441 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-14 10:32:00 +0000 (Fri, 14 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-07-12 10:32:49 +0530 (Wed, 12 Jul 2017)" );
	script_name( "Microsoft SharePoint Enterprise Server 2013 Remote Code Execution Vulnerability (KB3213559)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3213559." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because Microsoft Office fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft SharePoint Enterprise Server 2013." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3213559" );
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
if(IsMatchRegexp( shareVer, "^(15\\.)" )){
	path = path + "\\15.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4945.0999" )){
			report = "File checked:     " + path + "\\xlsrv.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4945.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

