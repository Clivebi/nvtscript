if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814543" );
	script_version( "2021-06-24T02:00:31+0000" );
	script_cve_id( "CVE-2018-8627" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-12 16:22:36 +0530 (Wed, 12 Dec 2018)" );
	script_name( "Microsoft SharePoint Server 2010 Service Pack 2 Information Disclosure Vulnerability (KB4461569)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4461569" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when Microsoft Excel software
  reads out of bound memory due to an uninitialized variable." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to disclose the contents of memory." );
	script_tag( name: "affected", value: "Microsoft SharePoint Server 2010 Service Pack 2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4461569" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:sharepoint_server" )){
	exit( 0 );
}
shareVer = infos["version"];
if(!shareVer){
	exit( 0 );
}
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( shareVer, "^14\\." )){
	path = path + "\\14.0\\Bin";
	dllVer = fetch_file_version( sysPath: path, file_name: "xlsrv.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7225.4999" )){
			report = report_fixed_ver( file_checked: path + "\\xlsrv.dll", file_version: dllVer, vulnerable_range: "14.0 - 14.0.7225.4999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

