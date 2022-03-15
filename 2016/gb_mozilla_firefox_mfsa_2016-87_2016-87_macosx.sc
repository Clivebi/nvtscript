CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809391" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2016-5287", "CVE-2016-5288" );
	script_bugtraq_id( 93810 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-10-21 15:25:13 +0530 (Fri, 21 Oct 2016)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2016-87_2016-87) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Crash in nsTArray_base<T>::SwapArrayElements.

  - Web content can read cache entries" );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to cause denial of service, and web
  content could access information in the HTTP cache which can reveal some
  visited URLs and the contents of those pages." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 49.0.2." );
	script_tag( name: "solution", value: "Update to version 49.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-87/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "49.0.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "49.0.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

