if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113752" );
	script_version( "2021-09-09T07:27:17+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 07:27:17 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-09-08 08:03:57 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 17:25:00 +0000 (Fri, 11 Sep 2020)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2020-24996", "CVE-2020-24999" );
	script_name( "Xpdf <= 4.02 Multiple DoS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_xpdf_detect.sc" );
	script_mandatory_keys( "Xpdf/Linux/Ver" );
	script_tag( name: "summary", value: "Xpdf is prone to multiple denial of service (DoS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-24996: Denial of service (DoS) in the pdftohtml binary because of an invalid memory
  access in the function TextString::~TextString() located in Catalog.cc.

  - CVE-2020-24999: Denial of service (DoS) in the pdftohtml binary because of an invalid memory
  access in the function fprintf located in Error.cc." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash the
  application." );
	script_tag( name: "affected", value: "Xpdf through version 4.02." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_xref( name: "URL", value: "https://forum.xpdfreader.com/viewtopic.php?f=3&t=42028" );
	script_xref( name: "URL", value: "https://forum.xpdfreader.com/viewtopic.php?f=3&t=42029" );
	exit( 0 );
}
CPE = "cpe:/a:foolabs:xpdf";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "4.02" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

