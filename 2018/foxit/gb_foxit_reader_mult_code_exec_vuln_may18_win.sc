CPE = "cpe:/a:foxitsoftware:reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812897" );
	script_version( "2021-05-31T06:00:14+0200" );
	script_cve_id( "CVE-2018-5674", "CVE-2018-5677", "CVE-2018-5676", "CVE-2018-5675", "CVE-2018-5678", "CVE-2018-5680", "CVE-2018-5679", "CVE-2018-7407", "CVE-2018-7406" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:14 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-08 17:11:00 +0000 (Fri, 08 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-25 15:43:57 +0530 (Fri, 25 May 2018)" );
	script_name( "Foxit Reader Multiple Code Execution Vulnerabilities - May18 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Foxit Reader and
  is prone to multiple code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Lack of proper validation of user-supplied data.

  - Foxit Reader unable to sanitize itself from crafted data in the PDF file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "Foxit Reader versions before 9.1 on
  windows." );
	script_tag( name: "solution", value: "Upgrade to Foxit Reader version 9.1
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/support/security-bulletins.php#content-2018" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_foxit_reader_detect_portable_win.sc" );
	script_mandatory_keys( "foxit/reader/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
pdfVer = infos["version"];
pdfPath = infos["location"];
if(version_is_less( version: pdfVer, test_version: "9.1" )){
	report = report_fixed_ver( installed_version: pdfVer, fixed_version: "9.1", install_path: pdfPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

