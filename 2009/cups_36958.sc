CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100344" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)" );
	script_bugtraq_id( 36958 );
	script_cve_id( "CVE-2009-2820" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "CUPS 'kerberos' Parameter Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36958" );
	script_xref( name: "URL", value: "http://www.cups.org/articles.php?L590" );
	script_xref( name: "URL", value: "http://www.cups.org" );
	script_xref( name: "URL", value: "http://www.cups.org/str.php?L3367" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-66-271169-1" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "affected", value: "This issue affects CUPS versions prior to 1.4.2." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "CUPS is prone to a cross-site scripting vulnerability because the
  application fails to sufficiently sanitize user-supplied input." );
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
if(version_is_less( version: vers, test_version: "1.4.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

