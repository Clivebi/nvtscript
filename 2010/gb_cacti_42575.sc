CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100764" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-08-30 14:30:07 +0200 (Mon, 30 Aug 2010)" );
	script_bugtraq_id( 42575 );
	script_cve_id( "CVE-2010-2543", "CVE-2010-2544", "CVE-2010-2545" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti Cross Site Scripting and HTML Injection Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42575" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=459105" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=459229" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Cacti is prone to cross-site-scripting and HTML-injection vulnerabilities
because it fails to properly sanitize user-supplied input before using it in dynamically generated content." );
	script_tag( name: "impact", value: "Attacker-supplied HTML and script code would run in the context of the affected browser, potentially allowing the
attacker to steal cookie-based authentication credentials or to control how the site is rendered to the user.
Other attacks are also possible." );
	script_tag( name: "affected", value: "Versions prior to Cacti 0.8.7g are vulnerable." );
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
if(version_is_less( version: vers, test_version: "0.8.7g" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.7g" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

