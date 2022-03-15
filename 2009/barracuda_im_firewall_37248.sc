CPE = "cpe:/h:barracuda_networks:barracuda_im_firewall";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100393" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-12-11 12:55:06 +0100 (Fri, 11 Dec 2009)" );
	script_bugtraq_id( 37248 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Barracuda IM Firewall 'smtp_test.cgi' Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37248" );
	script_xref( name: "URL", value: "http://www.barracudanetworks.com/ns/products/im_overview.php" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "barracuda_im_firewall_detect.sc" );
	script_mandatory_keys( "barracuda_im_firewall/detected" );
	script_tag( name: "summary", value: "Barracuda IM Firewall is prone to multiple cross-site scripting
  vulnerabilities because the application fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may help the
  attacker steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Barracuda IM Firewall 620 Firmware v4.0.01.003 is vulnerable.
  Other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "4.0.01.003" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

