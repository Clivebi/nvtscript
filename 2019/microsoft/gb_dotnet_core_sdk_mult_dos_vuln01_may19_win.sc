CPE = "cpe:/a:microsoft:.netcore_sdk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815128" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-0820", "CVE-2019-0980", "CVE-2019-0981" );
	script_bugtraq_id( 108207, 108232, 108245 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-16 11:38:35 +0530 (Thu, 16 May 2019)" );
	script_name( ".NET Core SDK Multiple DoS Vulnerabilities-01 (May 2019)" );
	script_tag( name: "summary", value: "This host is installed with ASP.NET Core SDK
  and is prone to multiple DoS vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - An error when .NET Core improperly process RegEx strings.

  - Multiple errors when .NET Core improperly handle web requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct DoS condition." );
	script_tag( name: "affected", value: "ASP.NET Core SDK 1.x prior to version 1.1.13" );
	script_tag( name: "solution", value: "Upgrade to ASP.NET Core 1.1.13 (.NET Core SDK
  1.1.13 includes .NET Core 1.0.16 Runtime) or 1.1.14 (.NET Core SDK 1.1.14 includes
  .NET Core 1.1.13 Runtime) or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0820" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0980" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0981" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/master/release-notes/1.0/1.0.16/1.0.16.md" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/master/release-notes/1.1/1.1.13/1.1.13.md" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( coreVers, "^1\\." ) && version_is_less( version: coreVers, test_version: "1.1.13" )){
	report = report_fixed_ver( installed_version: coreVers, fixed_version: "1.1.13 or 1.1.14", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

