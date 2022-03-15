CPE = "cpe:/a:foxitsoftware:phantompdf";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813264" );
	script_version( "2021-05-31T06:00:14+0200" );
	script_cve_id( "CVE-2018-14295", "CVE-2018-17706", "CVE-2018-17624", "CVE-2018-17622", "CVE-2018-17620", "CVE-2018-17621", "CVE-2018-17618", "CVE-2018-17619", "CVE-2018-17617", "CVE-2018-17615", "CVE-2018-17616" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:14 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-27 16:11:00 +0000 (Thu, 27 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-07-20 15:00:12 +0530 (Fri, 20 Jul 2018)" );
	script_name( "Foxit PhantomPDF 'JavaScript' Remote Code Execution Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Foxit PhantomPDF
  and is prone to multiple code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The user-after-free vulnerability that exists in the JavaScript, When
    executing embedded JavaScript code a document can be cloned. which frees
    a lot of used objects, but the JavaScript can continue to execute.

  - The use-after-free vulnerability found in the Javascript engine that can
    result in remote code execution." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to execute arbitrary code." );
	script_tag( name: "affected", value: "Foxit PhantomPDF versions before 9.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Foxit PhantomPDF version 9.2
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/support/security-bulletins.php#content-2018" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less( version: pdfVer, test_version: "9.2" )){
	report = report_fixed_ver( installed_version: pdfVer, fixed_version: "9.2", install_path: pdfPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

