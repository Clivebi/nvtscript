CPE = "cpe:/a:microsoft:asp.net_core";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815172" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-1075" );
	script_bugtraq_id( 108984 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-19 15:34:00 +0000 (Fri, 19 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-11 09:58:50 +0530 (Thu, 11 Jul 2019)" );
	script_name( ".NET Core Spoofing Vulnerability (July 2019)" );
	script_tag( name: "summary", value: "This host is installed with ASP.NET Core
  and is prone to spoofing vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in ASP.NET
  Core that could lead to an open redirect." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct Spoofing attack." );
	script_tag( name: "affected", value: "ASP.NET Core 2.1.x prior to version
  2.1.12 and 2.2.x prior to version 2.2.6" );
	script_tag( name: "solution", value: "Upgrade to ASP.NET Core SDK 2.1.12 or
  2.2.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/master/release-notes/2.2/2.2.6/2.2.6.md" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.12/2.1.12.md" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1075" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_asp_dotnet_core_detect_win.sc" );
	script_mandatory_keys( "ASP.NET/Core/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
coreVers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( coreVers, "^2\\.1" ) && version_is_less( version: coreVers, test_version: "2.1.12" ) ){
	fix = "2.1.12";
}
else {
	if(IsMatchRegexp( coreVers, "^2\\.2" ) && version_is_less( version: coreVers, test_version: "2.2.6" )){
		fix = "2.2.6";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: coreVers, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

