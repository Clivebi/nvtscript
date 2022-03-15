CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107443" );
	script_version( "2021-09-29T11:14:26+0000" );
	script_cve_id( "CVE-2018-0734", "CVE-2018-5407" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 11:14:26 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-09 12:18:54 +0100 (Wed, 09 Jan 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Tenable Nessus < 8.1.1 Multiple Vulnerabilities (TNS-2018-16)" );
	script_tag( name: "summary", value: "Nessus is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Tenable Nessus is affected by multiple vulnerabilities:

  - Tenable Nessus contains a flaw in the bundled third-party component OpenSSL library's DSA signature algorithm that renders it vulnerable to a timing side channel attack.

  - Tenable Nessus contains a flaw in the bundled third-party component OpenSSL library's Simultaneous Multithreading (SMT) architectures which render it vulnerable to side-channel leakage. This issue is known as 'PortSmash'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers potentially to recover the private key. They could possibly use this issue to perform a timing side-channel attack and recover private keys." );
	script_tag( name: "affected", value: "Nessus versions prior to version 8.1.1." );
	script_tag( name: "solution", value: "Update to version 8.1.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2018-16" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nessus_web_server_detect.sc" );
	script_mandatory_keys( "nessus/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "8.0.0", test_version2: "8.1.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.1.1", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

