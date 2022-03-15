CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810542" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_cve_id( "CVE-2017-3731", "CVE-2017-3732" );
	script_bugtraq_id( 95813, 95814 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 19:29:00 +0000 (Tue, 23 Apr 2019)" );
	script_tag( name: "creation_date", value: "2017-02-09 18:50:03 +0530 (Thu, 09 Feb 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OpenSSL Multiple Vulnerabilities Feb17" );
	script_tag( name: "summary", value: "OpenSSL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An out-of-bounds read error while using a specific cipher.

  - A carry propagating bug in the x86_64 Montgomery squaring procedure." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to conduct a denial of service attack and produce incorrect results." );
	script_tag( name: "affected", value: "OpenSSL 1.1.0 before 1.1.0d and
  1.0.2 before 1.0.2k" );
	script_tag( name: "solution", value: "Upgrade to OpenSSL version 1.1.0d or
  1.0.2k or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20170126.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc" );
	script_mandatory_keys( "openssl/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^1\\.1\\.0" ) ) {
	fix = "1.1.0d";
}
else {
	if(IsMatchRegexp( vers, "^1\\.0\\.1" )){
		fix = "1.0.2k";
	}
}
if(!fix){
	exit( 99 );
}
if(version_is_less( version: vers, test_version: fix )){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

