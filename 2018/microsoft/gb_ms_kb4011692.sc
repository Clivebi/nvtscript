if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813022" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-0919", "CVE-2018-0922" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-14 11:17:28 +0530 (Wed, 14 Mar 2018)" );
	script_name( "Microsoft Office Web Apps Server 2013 RCE And Information Disclosure Vulnerabilities (KB4011692)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011692" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Microsoft Office software reads out of bound memory due to an uninitialized
    variable.

  - Office software fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user. If the current user
  is logged on with administrative user rights, an attacker could take control
  of the affected system and also to view out of bound memory." );
	script_tag( name: "affected", value: "Microsoft Office Web Apps Server 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011692" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.5015.0999" )){
			report = report_fixed_ver( file_checked: path + "\\msoserver.dll", file_version: dllVer, vulnerable_range: "15.0 - 15.0.5015.0999" );
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

