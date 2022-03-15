CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100655" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-05-25 18:01:00 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-1644", "CVE-2010-1645" );
	script_bugtraq_id( 40332 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40332" );
	script_xref( name: "URL", value: "http://www.cacti.net/release_notes_0_8_7f.php" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/511393" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Cacti is prone to multiple cross-site scripting vulnerabilities because the
software fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in
the context of the affected site. This may allow the attacker to steal cookie-based authentication credentials and
to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to Cacti 0.8.7f are vulnerable." );
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
if(version_is_less( version: vers, test_version: "0.8.7f" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.8.7f" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

