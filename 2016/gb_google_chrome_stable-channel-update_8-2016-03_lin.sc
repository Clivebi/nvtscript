CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807616" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2016-1643", "CVE-2016-1644", "CVE-2016-1645" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-16 16:13:14 +0530 (Wed, 16 Mar 2016)" );
	script_name( "Google Chrome Security Update (stable-channel-update_8-2016-03) - Linux" );
	script_tag( name: "summary", value: "Google Chrome is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Type confusion in Blink.

  - Use-after-free in Blink.

  - Out-of-bounds write in PDFium." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to cause a denial of service
  (use-after-free) or possibly have unspecified other impact via a
  crafted HTML document." );
	script_tag( name: "affected", value: "Google Chrome version prior to 49.0.2623.87." );
	script_tag( name: "solution", value: "Update to version 49.0.2623.87 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/03/stable-channel-update_8.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "49.0.2623.87" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "49.0.2623.87", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

