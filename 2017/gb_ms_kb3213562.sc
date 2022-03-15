if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811745" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2017-8631", "CVE-2017-8742" );
	script_bugtraq_id( 100751, 100741 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-13 11:26:00 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-13 09:24:52 +0530 (Wed, 13 Sep 2017)" );
	script_name( "Microsoft Office Web Apps 2013 Service Pack 1 Multiple Vulnerabilities (KB3213562)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3213562" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist because Microsoft Office
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user and use a specially
  crafted file to perform actions in the security context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Office Web Apps 2013 Service Pack 1

  - Microsoft Excel Web App 2013 Service Pack 1

  - Microsoft Office Web Apps Server 2013 Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3213562" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_office_web_apps_detect.sc" );
	script_mandatory_keys( "MS/Office/Web/Apps/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:office_web_apps", exit_no_version: TRUE )){
	exit( 0 );
}
webappVer = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( webappVer, "^15\\." )){
	path = path + "\\PPTConversionService\\bin\\Converter";
	dllVer = fetch_file_version( sysPath: path, file_name: "msoserver.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4963.0999" )){
			report = "File checked:     " + path + "\\msoserver.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4963.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

