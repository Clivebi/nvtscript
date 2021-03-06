CPE = "cpe:/a:mercuryboard:mercuryboard";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16247" );
	script_version( "$Revision: 12861 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-21 10:53:04 +0100 (Fri, 21 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2005-0306", "CVE-2005-0307", "CVE-2005-0414", "CVE-2005-0460", "CVE-2005-0462", "CVE-2005-0662", "CVE-2005-0663", "CVE-2005-0878" );
	script_bugtraq_id( 12359, 12503, 12578, 12706, 12707, 12872 );
	script_name( "Multiple Vulnerabilities in MercuryBoard" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "MercuryBoard_detect.sc" );
	script_mandatory_keys( "MercuryBoard/detected" );
	script_tag( name: "solution", value: "Upgrade to MercuryBoard version 1.1.3." );
	script_tag( name: "summary", value: "The remote host is running MercuryBoard, a message board system written inPHP.

  Multiple vulnerabilities have been discovered in the product that allow an attacker to cause numerous cross site
  scripting attacks, inject arbitrary SQL statements and disclose the path under which the product has been
  installed." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: version, test_version: "1.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

