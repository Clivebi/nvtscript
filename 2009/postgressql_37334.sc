CPE = "cpe:/a:postgresql:postgresql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100400" );
	script_version( "2020-01-28T13:26:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-28 13:26:39 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2009-12-16 12:39:06 +0100 (Wed, 16 Dec 2009)" );
	script_bugtraq_id( 37334, 37333 );
	script_cve_id( "CVE-2009-4034", "CVE-2009-4136" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "PostgreSQL NULL Character CA SSL Certificate Validation Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "postgresql_detect.sc", "secpod_postgresql_detect_lin.sc", "secpod_postgresql_detect_win.sc" );
	script_mandatory_keys( "postgresql/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37334" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37333" );
	script_xref( name: "URL", value: "http://www.postgresql.org/about/news.1170" );
	script_tag( name: "summary", value: "PostgreSQL is prone to a security-bypass vulnerability because the
  application fails to properly validate the domain name in a signed CA certificate, allowing attackers
  to substitute malicious SSL certificates for trusted ones.

  PostgreSQL is also prone to a local privilege-escalation vulnerability." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows attackers to perform man-in-the-
  middle attacks or impersonate trusted servers, which will aid in further attacks.

  Exploiting the privilege-escalation vulnerability allows local attackers to gain elevated
  privileges." );
	script_tag( name: "affected", value: "PostgreSQL versions prior to 8.4.2, 8.3.9, 8.2.15, 8.1.19, 8.0.23, and
  7.4.27 are vulnerable to this issue." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
loc = infos["location"];
if(version_in_range( version: vers, test_version: "8.4", test_version2: "8.4.1" ) || version_in_range( version: vers, test_version: "8.3", test_version2: "8.3.8" ) || version_in_range( version: vers, test_version: "8.2", test_version2: "8.2.14" ) || version_in_range( version: vers, test_version: "8.1", test_version2: "8.1.18" ) || version_in_range( version: vers, test_version: "8.0", test_version2: "8.0.22" ) || version_in_range( version: vers, test_version: "7.4", test_version2: "7.4.26" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: loc );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

