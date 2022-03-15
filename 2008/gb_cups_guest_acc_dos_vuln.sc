CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800142" );
	script_version( "$Revision: 14010 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5183", "CVE-2008-5184" );
	script_bugtraq_id( 32419 );
	script_name( "CUPS Subscription Incorrectly uses Guest Account DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_xref( name: "URL", value: "http://www.cups.org/str.php?L2774" );
	script_xref( name: "URL", value: "http://www.gnucitizen.org/blog/pwning-ubuntu-via-cups/" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2008/11/19/3" );
	script_tag( name: "impact", value: "Successful exploitation causes Denial of Service condition." );
	script_tag( name: "affected", value: "CUPS Versions prior to 1.3.8 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to error in web interface (cgi-bin/admin.c), which
  uses the guest username when a user is not logged on to the web server.
  This leads to CSRF attacks with the add/cancel RSS subscription functions." );
	script_tag( name: "solution", value: "Upgrade to CUPS Version 1.3.8 or later." );
	script_tag( name: "summary", value: "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to Denial of Service Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_less( version: vers, test_version: "1.3.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

