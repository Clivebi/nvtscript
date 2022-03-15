CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107029" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2019-3961", "CVE-2019-3962" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-26 12:02:00 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-26 15:43:12 +0200 (Wed, 26 Jun 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Tenable Nessus <= 8.4.0 Multiple XSS Vulnerabilities (TNS-2019-04)" );
	script_tag( name: "summary", value: "This host is running Tenable Nessus and is prone to
  multiple XSS vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "For CVE-2019-3961, an unauthenticated, remote attacker could exploit
  this vulnerability via a specially crafted request to execute arbitrary script code in a user's browser session.

  For CVE-2019-3962, an authenticated, local attacker could exploit this vulnerability by convincing
  another targeted Nessus user to view a malicious URL and use Nessus to send fraudulent messages.
  Successful exploitation could allow the authenticated adversary to inject arbitrary text into the
  feed status, which will remain saved post session expiration." );
	script_tag( name: "affected", value: "Tenable Nessus through to version 8.4.0." );
	script_tag( name: "solution", value: "Upgrade to Tenable Nessus version 8.5.0 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2019-04" );
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
if(version_is_less( version: vers, test_version: "8.5.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.5.0", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

