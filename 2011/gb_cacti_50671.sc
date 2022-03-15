CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103319" );
	script_bugtraq_id( 50671 );
	script_cve_id( "CVE-2011-4824", "CVE-2014-2326" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti Unspecified SQL Injection and Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50671" );
	script_xref( name: "URL", value: "http://www.cacti.net/release_notes_0_8_7h.php" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-15 08:09:39 +0100 (Tue, 15 Nov 2011)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_tag( name: "solution", value: "The vendor has released fixes. Please see the references for details." );
	script_tag( name: "summary", value: "Cacti is prone to an SQL-injection vulnerability and a cross-site scripting
vulnerability because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to steal cookie-based authentication credentials, compromise the
application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Cacti 0.8.7g is vulnerable. Other versions may also be affected." );
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
if(version_is_less( version: vers, test_version: "0.8.7h" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.7h" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

