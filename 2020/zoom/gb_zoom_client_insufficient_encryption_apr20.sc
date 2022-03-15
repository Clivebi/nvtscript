CPE = "cpe:/a:zoom:zoom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108741" );
	script_version( "2021-09-30T13:55:33+0000" );
	script_cve_id( "CVE-2020-11500" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 13:55:33 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-07 13:46:00 +0000 (Tue, 07 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-06 08:11:24 +0000 (Mon, 06 Apr 2020)" );
	script_name( "Zoom Client Insufficient Video and Audio Encryption (Apr 2020)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_zoom_client_detect_macosx.sc", "gb_zoom_client_detect_win.sc" );
	script_mandatory_keys( "zoom/client/detected" );
	script_xref( name: "URL", value: "https://citizenlab.ca/2020/04/move-fast-roll-your-own-crypto-a-quick-look-at-the-confidentiality-of-zoom-meetings/" );
	script_xref( name: "URL", value: "https://explore.zoom.us/en/trust/security/security-bulletin/" );
	script_tag( name: "summary", value: "Zoom Client is using insufficient video and audio encryption
  for Meetings." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Zoom Client for Meetings uses the ECB mode of AES for video and
  audio encryption. Within a meeting, all participants use a single 128-bit key." );
	script_tag( name: "affected", value: "All current Zoom Client versions are known to be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( get_kb_item( "zoom/client/mac/detected" ) ) {
	check = "4.6.919273.0402";
}
else {
	if( get_kb_item( "zoom/client/win/detected" ) ) {
		check = "4.6.919253.0401";
	}
	else {
		check = "3.5.374815.0324";
	}
}
if(version_is_less_equal( version: vers, test_version: check )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

