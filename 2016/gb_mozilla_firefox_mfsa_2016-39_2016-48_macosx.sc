CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807679" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2016-2820", "CVE-2016-2808", "CVE-2016-2817", "CVE-2016-2816", "CVE-2016-2814", "CVE-2016-2811", "CVE-2016-2812", "CVE-2016-2807", "CVE-2016-2806", "CVE-2016-2804" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-02 12:27:09 +0530 (Mon, 02 May 2016)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2016-39_2016-48) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to conduct Universal XSS
  (UXSS) attacks, to execute arbitrary code, to bypass the Content
  Security Policy (CSP) protection mechanism, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 46." );
	script_tag( name: "solution", value: "Update to version 46 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-48/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-47/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-46/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-45/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-44/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-43/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-42/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-41/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-40/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-39/" );
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
if(version_is_less( version: vers, test_version: "46" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "46", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

