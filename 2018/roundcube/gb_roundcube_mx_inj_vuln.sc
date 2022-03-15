CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140959" );
	script_version( "2021-06-03T03:24:46+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 03:24:46 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-10 13:53:54 +0700 (Tue, 10 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-24 17:12:00 +0000 (Thu, 24 May 2018)" );
	script_cve_id( "CVE-2018-9846" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail < 1.3.6 MX Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "In Roundcube from versions 1.2.0 to 1.3.5, with the archive plugin enabled
and configured, it's possible to exploit the unsanitized, user-controlled '_uid' parameter to perform an MX (IMAP)
injection attack by placing an IMAP command after a %0d%0a sequence.

NOTE: this is less easily exploitable in 1.3.4 and later because of a Same Origin Policy protection mechanism." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions 1.2.0 to 1.3.5." );
	script_tag( name: "solution", value: "Update to version 1.3.6 or later." );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/6229" );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/6238" );
	script_xref( name: "URL", value: "https://medium.com/@ndrbasi/cve-2018-9846-roundcube-303097048b0a" );
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
version = infos["version"];
path = infos["location"];
if(version_in_range( version: version, test_version: "1.2.0", test_version2: "1.3.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

