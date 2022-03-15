CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107633" );
	script_version( "2021-09-29T11:39:12+0000" );
	script_cve_id( "CVE-2019-1559", "CVE-2017-18214", "CVE-2016-4055" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-29 11:39:12 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-11 18:15:00 +0000 (Sun, 11 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-04-02 15:40:22 +0200 (Tue, 02 Apr 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Tenable Nessus < 8.3.0 Multiple Vulnerabilities (TNS-2019-02)" );
	script_tag( name: "summary", value: "Nessus is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "These vulnerabilities exist in third party components used by Nessus:

  - An Information disclosure vulnerability in OpenSSL.

  - A denial of service (DoS) vulnerability in the moment module before 2.19.3 for Node.js.

  - A denial of service (DoS) vulnerability in the duration function in the moment package before 2.11.2
    for Node.js." );
	script_tag( name: "impact", value: "An unauthenticated, remote attacker may be able to:

  - obtain sensitive information, caused by the failure to immediately close the TCP connection after
    the hosts encounter a zero-length record with valid padding. (CVE-2019-1559)

  - to cause CPU consumption via regular expression of crafted date string
    different than CVE-2016-4055. (CVE-2017-18214)

  - to cause CPU consumption via date string ReDoS. (CVE-2016-4055)" );
	script_tag( name: "affected", value: "Nessus versions prior to version 8.3.0." );
	script_tag( name: "solution", value: "Update to version 8.3.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2019-02" );
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
if(version_is_less( version: vers, test_version: "8.3.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.3.0", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

