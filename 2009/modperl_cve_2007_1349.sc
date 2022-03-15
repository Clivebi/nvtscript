CPE = "cpe:/a:apache:mod_perl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100162" );
	script_version( "2021-07-06T13:33:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 13:33:45 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 23192 );
	script_cve_id( "CVE-2007-1349" );
	script_name( "Apache mod_perl Path_Info Remote DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_mod_perl_http_detect.sc" );
	script_mandatory_keys( "apache/mod_perl/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/23192" );
	script_tag( name: "summary", value: "According to its version number, the remote version of the
  Apache mod_perl module is prone to a remote denial of service (DoS) vulnerability." );
	script_tag( name: "impact", value: "Successful exploits may allow remote attackers to cause
  DoS conditions on the webserver running the mod_perl module." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more
  information." );
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
if(version_is_equal( version: vers, test_version: "2.0.3" ) || version_is_equal( version: vers, test_version: "2.0.2" ) || version_is_equal( version: vers, test_version: "2.0.1" ) || version_is_equal( version: vers, test_version: "1.29" ) || version_is_equal( version: vers, test_version: "1.27" ) || version_is_equal( version: vers, test_version: "1.99" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

