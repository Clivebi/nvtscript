CPE = "cpe:/a:igniterealtime:openfire";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900484" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-6511", "CVE-2008-6510", "CVE-2008-6508", "CVE-2008-6509" );
	script_bugtraq_id( 32189 );
	script_name( "Openfire Multiple Vulnerabilities (Mar09)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openfire_detect.sc" );
	script_require_ports( "Services/www", 9090 );
	script_mandatory_keys( "OpenFire/Installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32478" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7075" );
	script_xref( name: "URL", value: "http://www.andreas-kurtz.de/advisories/AKADV2008-001-v1.0.txt" );
	script_xref( name: "URL", value: "http://www.igniterealtime.org/builds/openfire/docs/latest/changelog.html" );
	script_tag( name: "affected", value: "Openfire version prior to 3.6.1" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - error in the AuthCheckFilter which causes access to administrative
  resources without admin authentication.

  - error in the type parameter inside the file 'sipark-log-summary.jsp'
  which causes SQL Injection attack.

  - error in the 'login.jsp' URL parameter which accept malicious chars
  as input which causes XSS attack.

  - error in the SIP-Plugin which is deactivated by default which lets the
  attack install the plugin by using admin authentication bypass methods." );
	script_tag( name: "solution", value: "Upgrade to the version 3.6.1 or later." );
	script_tag( name: "summary", value: "This host is running Openfire and is prone to multiple
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause multiple attacks in
  the context of the application i.e. Cross site scripting, disclosure of
  sensitive information, phishing attacks through the affected parameters." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "3.6.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.6.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

