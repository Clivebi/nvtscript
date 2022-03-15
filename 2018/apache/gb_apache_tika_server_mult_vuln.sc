if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113167" );
	script_version( "2021-06-14T11:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 11:00:34 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-26 11:12:13 +0200 (Thu, 26 Apr 2018)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-1335", "CVE-2018-1338", "CVE-2018-1339" );
	script_name( "Apache Tika Server 1.17 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_tika_server_detect.sc" );
	script_mandatory_keys( "Apache/Tika/Server/Installed" );
	script_tag( name: "summary", value: "Apache Tika Server is prone to multiple vulnerabilities,
  including Command Execution and Denial of Service" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  In Apache Tika, clients could send carefully crafted headers to tika-server that could be used to inject commands
  into the command line of the server running tika-server.
  This vulnerability only affects those running tika-server on a server that is open to untrusted clients.

  A carefully crafted (or fuzzed) file can trigger an infinite loop in Apache Tika's BPGParser.

  A carefully crafted (or fuzzed) file can trigger an infinite loop in Apache Tika's ChmParser." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to eventually gain full control
  over the target system." );
	script_tag( name: "affected", value: "Apache Tika Server through version 1.17." );
	script_tag( name: "solution", value: "Update to version 1.18." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/b3ed4432380af767effd4c6f27665cc7b2686acccbefeb9f55851dca@%3Cdev.tika.apache.org%3E" );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/4d20c5748fb9f836653bc78a1bad991ba8485d82a1e821f70b641932@%3Cdev.tika.apache.org%3E" );
	exit( 0 );
}
CPE = "cpe:/a:apache:tika";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.18" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

