CPE = "cpe:/a:teamviewer:teamviewer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.118116" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_cve_id( "CVE-2021-34803" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 18:05:00 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-21 14:28:22 +0200 (Mon, 21 Jun 2021)" );
	script_name( "TeamViewer Loading Of Untrusted DLLs (CVE-2021-34803) - Windows" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_teamviewer_win_detect.sc" );
	script_mandatory_keys( "teamviewer/Ver" );
	script_tag( name: "summary", value: "TeamViewer is prone to a vulnerability that allows loading of
  untrusted DLLs into the service process." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "The update implements a measure to prevent a Microsoft Windows
  system DLL from loading untrusted DLLs from the application directory into the service process." );
	script_tag( name: "affected", value: "TeamViewer version prior to 9.0.259145, 10.x prior to
  10.0.259144, 11.x prior to 11.0.259143, 12.x prior to 12.0.259142, 13.x prior to 13.2.36222, 14.x
  prior to 14.2.56678, 14.x starting from 14.3 and prior to 14.7.48644, 15.x prior to 15.15.5." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111147/windows-v9-0-2591451" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111149/windows-v10-0-259144" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111150/windows-v11-0-259143" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111151/windows-v12-0-259142" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111152/windows-v13-2-36222" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111153/windows-v14-2-56678" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111154/windows-v14-7-48644" );
	script_xref( name: "URL", value: "https://community.teamviewer.com/English/discussion/111125/windows-v15-15-5" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if( version_is_less( version: version, test_version: "9.0.259145" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.259145", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
else {
	if( IsMatchRegexp( version, "^10\\.0" ) && version_is_less( version: version, test_version: "10.0.259144" ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "10.0.259144", install_path: location );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if( IsMatchRegexp( version, "^11\\.0" ) && version_is_less( version: version, test_version: "11.0.259143" ) ){
			report = report_fixed_ver( installed_version: version, fixed_version: "11.0.259143", install_path: location );
			security_message( port: 0, data: report );
			exit( 0 );
		}
		else {
			if( IsMatchRegexp( version, "^12\\.0" ) && version_is_less( version: version, test_version: "12.0.259142" ) ){
				report = report_fixed_ver( installed_version: version, fixed_version: "12.0.259142", install_path: location );
				security_message( port: 0, data: report );
				exit( 0 );
			}
			else {
				if( IsMatchRegexp( version, "^13\\.[0-2]" ) && version_is_less( version: version, test_version: "13.2.36222" ) ){
					report = report_fixed_ver( installed_version: version, fixed_version: "13.2.36222", install_path: location );
					security_message( port: 0, data: report );
					exit( 0 );
				}
				else {
					if( IsMatchRegexp( version, "^14\\.[0-2]" ) && version_is_less( version: version, test_version: "14.2.56678" ) ){
						report = report_fixed_ver( installed_version: version, fixed_version: "14.2.56678", install_path: location );
						security_message( port: 0, data: report );
						exit( 0 );
					}
					else {
						if( IsMatchRegexp( version, "^14\\.[3-7]" ) && version_is_less( version: version, test_version: "14.7.48644" ) ){
							report = report_fixed_ver( installed_version: version, fixed_version: "14.7.48644", install_path: location );
							security_message( port: 0, data: report );
							exit( 0 );
						}
						else {
							if(IsMatchRegexp( version, "^15\\.([0-9]|1[0-5])\\." ) && version_is_less( version: version, test_version: "15.15.5" )){
								report = report_fixed_ver( installed_version: version, fixed_version: "15.15.5", install_path: location );
								security_message( port: 0, data: report );
								exit( 0 );
							}
						}
					}
				}
			}
		}
	}
}
exit( 99 );

