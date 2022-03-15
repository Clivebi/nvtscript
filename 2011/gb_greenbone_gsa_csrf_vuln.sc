CPE = "cpe:/a:greenbone:greenbone_security_assistant";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801919" );
	script_version( "$Revision: 13882 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-26 14:07:41 +0100 (Tue, 26 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0650" );
	script_name( "Greenbone Security Assistant Cross-Site Request Forgery Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gsa_detect.sc" );
	script_require_ports( "Services/www", 80, 443, 9392 );
	script_mandatory_keys( "greenbone_security_assistant/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to conduct cross-site
  request forgery attacks." );
	script_tag( name: "affected", value: "Greenbone Security Assistant version prior to 2.0.0." );
	script_tag( name: "insight", value: "The application allows users to perform certain actions via HTTP
  requests without performing any validity checks to verify the requests. This
  can be exploited to execute arbitrary commands in OpenVAS Manager by tricking
  a logged in administrative user into visiting a malicious web site." );
	script_tag( name: "solution", value: "Update Greenbone Security Assistant to version 2.0.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Greenbone Security Assistant and is
  prone to cross-site request forgery vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43092" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65012" );
	script_xref( name: "URL", value: "http://www.openvas.org/OVSA20110118.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/515971/100/0/threaded" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less( version: vers, test_version: "2.0.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.0.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

