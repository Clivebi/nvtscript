CPE = "cpe:/a:centreon:centreon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100428" );
	script_version( "$Revision: 13960 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-01-06 10:44:19 +0100 (Wed, 06 Jan 2010)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4368" );
	script_bugtraq_id( 37383 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Centreon Authentication Mechanism Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37383" );
	script_xref( name: "URL", value: "http://www.centreon.com/Development/changelog-2x.html" );
	script_xref( name: "URL", value: "http://www.centreon.com/" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "centreon_detect.sc" );
	script_mandatory_keys( "centreon/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Centreon is prone to a security-bypass vulnerability.

An attacker can exploit this issue to bypass certain security restrictions and gain unauthorized access to certain
functionality, which may lead to further attacks.

Versions prior to Centreon 2.1.4 are vulnerable." );
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
if(version_is_less( version: vers, test_version: "2.1.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.1.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

