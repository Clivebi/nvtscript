CPE = "cpe:/a:microsoft:remote_desktop_connection";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818184" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-34535" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-23 20:57:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 17:35:18 +0530 (Wed, 11 Aug 2021)" );
	script_name( "Remote Desktop Client RCE Vulnerability (Windows)" );
	script_tag( name: "summary", value: "Remote Desktop Client is prone to RCE vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error in
  Remote Desktop Client." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on affected system." );
	script_tag( name: "affected", value: "Remote Desktop Client prior to public
  version 1.2.2223 on Windows" );
	script_tag( name: "solution", value: "Update Remote Desktop Client to public
  version 1.2.2223 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/windowsdesktop-whatsnew" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_remote_desktop_client_detect_win.sc" );
	script_mandatory_keys( "remote/desktop/client/win/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
rdVer = infos["version"];
rdPath = infos["location"];
if(version_is_less( version: rdVer, test_version: "1.2.2223" )){
	report = report_fixed_ver( installed_version: rdVer, fixed_version: "1.2.2223", install_path: rdPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

