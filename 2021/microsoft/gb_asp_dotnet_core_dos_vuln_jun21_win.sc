CPE = "cpe:/a:microsoft:asp.net_core";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818324" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-31957" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-07 15:08:00 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 10:10:36 +0530 (Thu, 10 Jun 2021)" );
	script_name( ".NET Core Denial of Service Vulnerability - June21" );
	script_tag( name: "summary", value: "ASP.NET Core is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error in
  the Microsoft ASP.NET Core" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct a denial of service attack on the affected system." );
	script_tag( name: "affected", value: "ASP.NET Core version 5.0 and 3.1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.7/5.0.7.md" );
	script_xref( name: "URL", value: "https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.16/3.1.16.md" );
	script_xref( name: "URL", value: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31957" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
if( IsMatchRegexp( coreVers, "^3\\.1" ) && version_is_less( version: coreVers, test_version: "3.1.16" ) ){
	fix = "3.1.16";
}
else {
	if(IsMatchRegexp( coreVers, "^5\\.0" ) && version_is_less( version: coreVers, test_version: "5.0.7" )){
		fix = "5.0.7";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: coreVers, fixed_version: fix, install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

