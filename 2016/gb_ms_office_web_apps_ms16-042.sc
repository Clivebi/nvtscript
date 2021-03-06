CPE = "cpe:/a:microsoft:office_web_apps";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807542" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0127" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-04-13 11:57:14 +0530 (Wed, 13 Apr 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Web Apps Memory Corruption Vulnerability (3148775)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-042." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the Office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to execute arbitrary code in the context of the current user and to
  take control  of the affected system." );
	script_tag( name: "affected", value: "- Microsoft Office Web Apps 2010 Service Pack 2 and prior

  - Microsoft Office Web Apps Server 2013 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3114934" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-042" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_office_web_apps_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Web/Apps/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
webappVer = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( webappVer, "^15\\..*" )){
	path = path + "\\PPTConversionService\\bin\\Converter\\";
	dllVer = fetch_file_version( sysPath: path, file_name: "msoserver.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "15.0", test_version2: "15.0.4815.0999" )){
			report = "File checked:     " + path + "msoserver.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4815.0999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

