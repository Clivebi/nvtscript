CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108457" );
	script_version( "2021-06-08T13:53:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-08 13:53:29 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-26 17:24:50 +0200 (Sun, 26 Aug 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-13 00:03:00 +0000 (Thu, 13 Dec 2018)" );
	script_cve_id( "CVE-2018-19205" );
	script_name( "Roundcube Webmail < 1.3.7 Enigma Plugin PGP Vulnerability (EFAIL)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to an information disclosure
  vulnerability in the Enigma Plugin." );
	script_tag( name: "insight", value: "Roundcube Webmail with enabled PGP support via the Enigma Plugin
  mishandle the Modification Detection Code (MDC) feature or accept an obsolete packet type which
  can indirectly lead to plaintext exfiltration, aka EFAIL." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail prior to version 1.3.7." );
	script_tag( name: "solution", value: "Update to version 1.3.7 or later." );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/6289" );
	script_xref( name: "URL", value: "https://roundcube.net/news/2018/07/27/update-1.3.7-released" );
	script_xref( name: "URL", value: "https://efail.de/" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
loc = infos["location"];
if(version_is_less( version: vers, test_version: "1.3.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.7", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

