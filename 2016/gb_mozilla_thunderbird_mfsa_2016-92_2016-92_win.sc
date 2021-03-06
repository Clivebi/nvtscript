CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809828" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2016-9079" );
	script_bugtraq_id( 94591 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-01 13:38:43 +0530 (Thu, 01 Dec 2016)" );
	script_name( "Mozilla Thunderbird Security Update (mfsa_2016-92_2016-92) - Windows" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw exists due to:
  Use-after-free in SVG Animation." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to cause a denial of service via application crash,
  or execute arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Thunderbird versions before 45.5.1." );
	script_tag( name: "solution", value: "Update to version 45.5.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-92" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "45.5.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "45.5.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

