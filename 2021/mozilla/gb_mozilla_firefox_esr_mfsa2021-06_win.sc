CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817910" );
	script_version( "2021-06-23T12:49:39+0000" );
	script_cve_id( "CVE-2020-16048" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-23 12:49:39 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-09 12:54:56 +0530 (Tue, 09 Feb 2021)" );
	script_name( "Mozilla Firefox ESR Security Update (mfsa2021-06) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox ESR is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a buffer overflow error
  in depth pitch calculations for compressed textures." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to run arbitrary code or cause denial of service." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before 78.7.1
  on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox ESR version
  78.7.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2021-06/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "78.7.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "78.7.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

