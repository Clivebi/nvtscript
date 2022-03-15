CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100150" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-04-17 18:35:24 +0200 (Fri, 17 Apr 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-0163" );
	script_bugtraq_id( 34571 );
	script_name( "CUPS '_cupsImageReadTIFF()' Integer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34571" );
	script_xref( name: "URL", value: "http://www.cups.org/str.php?L3031" );
	script_tag( name: "impact", value: "Successful exploits may allow attackers to execute arbitrary code
  with the privileges of a user running the utilities. Failed exploit attempts likely cause
  denial-of-service conditions." );
	script_tag( name: "affected", value: "CUPS versions prior to 1.3.10." );
	script_tag( name: "solution", value: "Update to version 1.3.10 or later." );
	script_tag( name: "summary", value: "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to an Integer Overflow Vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.cups.org/software.php" );
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
if(!IsMatchRegexp( vers, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.3.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

