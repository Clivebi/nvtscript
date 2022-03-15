CPE = "cpe:/a:adobe:media_encoder";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817250" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-9649", "CVE-2020-9650", "CVE-2020-9646" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-22 20:50:00 +0000 (Wed, 22 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-27 11:25:34 +0530 (Mon, 27 Jul 2020)" );
	script_name( "Adobe Media Encoder Security Update (APSB20-36) - Windows" );
	script_tag( name: "summary", value: "Adobe Media Encoder is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple out-of-bounds write error.

  - An out-of-bounds read error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to conduct arbitrary code execution and disclose sensitive information." );
	script_tag( name: "affected", value: "Adobe Media Encoder 14.2 and earlier versions." );
	script_tag( name: "solution", value: "Update to Adobe Media Encoder 14.3
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/media-encoder/apsb20-36.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_media_encoder_detect_win.sc" );
	script_mandatory_keys( "adobe/mediaencoder/win/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "14.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "14.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

