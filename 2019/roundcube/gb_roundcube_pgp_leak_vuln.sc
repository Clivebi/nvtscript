CPE = "cpe:/a:roundcube:webmail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142410" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-05-15 08:05:42 +0000 (Wed, 15 May 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-24 18:15:00 +0000 (Thu, 24 Sep 2020)" );
	script_cve_id( "CVE-2019-10740" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Roundcube Webmail < 1.3.10 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_roundcube_detect.sc" );
	script_mandatory_keys( "roundcube/detected" );
	script_tag( name: "summary", value: "Roundcube Webmail is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "In Roundcube Webmail, an attacker in possession of S/MIME or PGP encrypted
  emails can wrap them as sub-parts within a crafted multipart email. The encrypted part(s) can further be hidden
  using HTML/CSS or ASCII newline characters. This modified multipart email can be re-sent by the attacker to the
  intended receiver. If the receiver replies to this (benign looking) email, they unknowingly leak the plaintext
  of the encrypted message part(s) back to the attacker." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Roundcube Webmail versions 1.3.9 and prior." );
	script_tag( name: "solution", value: "Update to version 1.3.10 or later." );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/issues/6638" );
	script_xref( name: "URL", value: "https://github.com/roundcube/roundcubemail/releases/tag/1.3.10" );
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
if(version_is_less_equal( version: version, test_version: "1.3.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.3.10", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

