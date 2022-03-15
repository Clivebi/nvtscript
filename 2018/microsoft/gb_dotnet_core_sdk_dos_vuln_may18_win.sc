CPE = "cpe:/a:microsoft:.netcore_sdk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813190" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-0765" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-14 18:01:00 +0000 (Thu, 14 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-15 14:17:38 +0530 (Tue, 15 May 2018)" );
	script_name( ".NET Core SDK Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with .NET Core SDK
  and is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when .NET
  and .NET Core improperly process XML documents." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause a denial of service against a .NET application." );
	script_tag( name: "affected", value: ".NET Core SDK 2.x prior to version 2.1.200" );
	script_tag( name: "solution", value: "Upgrade to .NET Core SDK to version 2.1.200
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0765" );
	script_xref( name: "URL", value: "https://github.com/dotnet/announcements/issues/67" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/master/release-notes/download-archives/2.1.200-sdk-download.md" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_asp_dotnet_core_detect_win.sc" );
	script_mandatory_keys( ".NET/Core/SDK/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
coreVers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( coreVers, "^(2\\.)" ) && version_is_less( version: coreVers, test_version: "2.1.200" )){
	report = report_fixed_ver( installed_version: coreVers, fixed_version: "2.1.200", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

