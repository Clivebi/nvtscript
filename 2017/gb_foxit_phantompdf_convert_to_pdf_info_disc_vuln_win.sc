CPE = "cpe:/a:foxitsoftware:phantompdf";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809874" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-5556" );
	script_bugtraq_id( 95353 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-26 18:14:00 +0000 (Thu, 26 Jan 2017)" );
	script_tag( name: "creation_date", value: "2017-01-24 12:33:27 +0530 (Tue, 24 Jan 2017)" );
	script_name( "Foxit PhantomPDF 'ConvertToPDF plugin' Information Disclosure Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Foxit PhantomPDF
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the ConvertToPDF plugin
  does not properly handle a crafted JPEG image." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to get sensitive information, also an attacker can leverage this in
  conjunction with other vulnerabilities to execute code in the context of the
  current process." );
	script_tag( name: "affected", value: "Foxit PhantomPDF version prior to 8.2" );
	script_tag( name: "solution", value: "Upgrade to Foxit PhantomPDF version
  8.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-17-039" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/support/security-bulletins.php" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_foxit_phantom_reader_detect.sc" );
	script_mandatory_keys( "foxit/phantompdf/ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!foxitVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: foxitVer, test_version: "8.2" )){
	report = report_fixed_ver( installed_version: foxitVer, fixed_version: "8.2" );
	security_message( data: report );
	exit( 0 );
}

