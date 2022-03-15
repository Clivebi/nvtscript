CPE = "cpe:/a:moinmo:moinmoin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100696" );
	script_version( "$Revision: 13960 $" );
	script_cve_id( "CVE-2010-2969", "CVE-2010-2970", "CVE-2010-2487" );
	script_bugtraq_id( 40549 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)" );
	script_name( "MoinMoin 'PageEditor.py' Cross-Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moinmoin_wiki_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "moinmoinWiki/installed" );
	script_xref( name: "URL", value: "http://moinmo.in/SecurityFixes" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40549" );
	script_xref( name: "URL", value: "http://moinmo.in/MoinMoinBugs/1.9.2UnescapedInputForThemeAddMsg" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may help the attacker steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "MoinMoin 1.9.2 and prior are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "MoinMoin is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied input data." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less_equal( version: vers, test_version: "1.9.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.9.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

