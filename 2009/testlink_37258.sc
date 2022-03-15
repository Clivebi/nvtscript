CPE = "cpe:/a:testlink:testlink";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100390" );
	script_version( "2020-03-11T12:22:13+0000" );
	script_tag( name: "last_modification", value: "2020-03-11 12:22:13 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-12-10 18:09:58 +0100 (Thu, 10 Dec 2009)" );
	script_bugtraq_id( 37258 );
	script_cve_id( "CVE-2009-4237", "CVE-2009-4238" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "TestLink Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "testlink_detect.sc" );
	script_mandatory_keys( "testlink/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "TestLink is prone to multiple SQL-injection and cross-site scripting
  vulnerabilities because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to steal cookie-based authentication
  credentials, compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Versions prior to TestLink 1.8.5 are vulnerable." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37258" );
	script_xref( name: "URL", value: "http://www.teamst.org/index.php?option=com_content&task=view&id=84&Itemid=2" );
	script_xref( name: "URL", value: "http://www.coresecurity.com/content/testlink-multiple-injection-vulnerabilities" );
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
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.8.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

