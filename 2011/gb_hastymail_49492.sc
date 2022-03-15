if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103244" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-08 12:04:18 +0200 (Thu, 08 Sep 2011)" );
	script_bugtraq_id( 49492 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Hastymail2 Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49492" );
	script_xref( name: "URL", value: "http://www.hastymail.org/" );
	script_xref( name: "URL", value: "http://hastymail.svn.sourceforge.net/viewvc/hastymail/trunk/hastymail2/CHANGES?revision=1983" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_hastymail2_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "hastymail2/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Hastymail2 is prone to multiple cross-site scripting vulnerabilities
  because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to Hastymail2 1.1 RC1 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "Hastymail2" )){
	if(version_is_less( version: vers, test_version: "1.1 RC1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "1.1RC1" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

