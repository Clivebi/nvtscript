CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100599" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)" );
	script_cve_id( "CVE-2010-1431" );
	script_bugtraq_id( 39639 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Cacti Multiple Input Validation Security Vulnerabilities" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39639" );
	script_xref( name: "URL", value: "http://www.bonsai-sec.com/en/research/vulnerabilities/cacti-os-command-injection-0105.php" );
	script_xref( name: "URL", value: "http://www.bonsai-sec.com/en/research/vulnerabilities/cacti-sql-injection-0104.php" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_tag( name: "solution", value: "Updates are available to address the SQL-injection issue. Please see the
  references for more information." );
	script_tag( name: "summary", value: "Cacti is prone to multiple input-validation vulnerabilities because it fails
  to adequately sanitize user-supplied input. These vulnerabilities include SQL-injection and command-injection issues." );
	script_tag( name: "impact", value: "Exploiting these issues can allow an attacker to compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database. Other attacks may also be possible." );
	script_tag( name: "affected", value: "Cacti 0.8.7e is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "0.8.7e" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.7e" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

