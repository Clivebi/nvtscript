if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100883" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-11-01 13:16:04 +0100 (Mon, 01 Nov 2010)" );
	script_bugtraq_id( 44556, 44557 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "FrontAccounting Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44556" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44557" );
	script_xref( name: "URL", value: "http://frontaccounting.com/" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/frontaccounting/" );
	script_xref( name: "URL", value: "http://frontaccounting.com/wb3/pages/posts/release-2.3-rc3157.php" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_frontaccounting_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "frontaccounting/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "summary", value: "FrontAccounting is prone to multiple cross-site scripting
  vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "FrontAccounting 2.3RC2 is vulnerable, other versions may also
  be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "FrontAccounting" )){
	if(version_is_less( version: vers, test_version: "2.3.RC3" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.RC3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

