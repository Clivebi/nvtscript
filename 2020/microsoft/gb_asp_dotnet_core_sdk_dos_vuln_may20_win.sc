CPE = "cpe:/a:microsoft:.netcore_sdk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817111" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-1108" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-18 15:03:00 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2020-05-13 09:18:00 +0530 (Wed, 13 May 2020)" );
	script_name( ".NET Core SDK DoS Vulnerability (May 2020)" );
	script_tag( name: "summary", value: "ASP.NET Core SDK is prone to a denail-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when .NET
  Core or .NET Framework improperly handles web requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct DoS attacks." );
	script_tag( name: "affected", value: "ASP.NET Core SDK 2.1.x prior to 2.1.514 and 3.1.x
  prior to 3.1.104" );
	script_tag( name: "solution", value: "Update to ASP.NET Core SDK to 3.1.104 or
  2.1.514 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/master/release-notes/3.1/3.1.4/3.1.4.md" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.18/2.1.18.md" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1108" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^2\\.1" ) && version_is_less( version: vers, test_version: "2.1.514" ) ){
	fix = "2.1.514";
}
else {
	if(IsMatchRegexp( vers, "^3\\.1" ) && version_is_less( version: vers, test_version: "3.1.104" )){
		fix = "3.1.104";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

