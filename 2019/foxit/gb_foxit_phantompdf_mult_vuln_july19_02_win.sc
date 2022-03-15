CPE = "cpe:/a:foxitsoftware:phantompdf";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815266" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_cve_id( "CVE-2019-14208", "CVE-2019-14209", "CVE-2019-14210", "CVE-2019-14214" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-25 15:41:14 +0530 (Thu, 25 Jul 2019)" );
	script_name( "Foxit PhantomPDF Multiple Vulnerabilities-July 2019 (Windows)-02" );
	script_tag( name: "summary", value: "The host is installed with Foxit PhantomPDF and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An issue in getting a PDF object from a document, or parsing a certain portfolio
    that contains a null dictionary which could expose the application to a NULL pointer
    dereference.

  - Data desynchrony when adding AcroForm could cause Heap Corruption.

  - Use of an invalid pointer copy, resulting from a destructed string object
    could cause Memory Corruption.

  - Deleting pages in a document that contains only one page by calling a
    't.hidden = true' function could result in JavaScript Denial of Service." );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers
  to overflow the buffer and cause denial of service conditions." );
	script_tag( name: "affected", value: "Foxit PhantomPDF versions 8.3.9.41099 and prior
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Foxit PhantomPDF 8.3.10 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/pdf-editor/" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/support/security-bulletins.php" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_foxit_phantom_reader_detect.sc" );
	script_mandatory_keys( "foxit/phantompdf/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
pdfVer = infos["version"];
pdfPath = infos["location"];
if(version_is_less_equal( version: pdfVer, test_version: "8.3.9.41099" )){
	report = report_fixed_ver( installed_version: pdfVer, fixed_version: "8.3.10", install_path: pdfPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

