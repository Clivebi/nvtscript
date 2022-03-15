CPE = "cpe:/a:horde:imp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15616" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 4444 );
	script_cve_id( "CVE-2002-0181" );
	script_xref( name: "OSVDB", value: "5345" );
	script_name( "Horde IMP status.php3 XSS" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "imp_detect.sc" );
	script_mandatory_keys( "horde/imp/detected" );
	script_tag( name: "solution", value: "Upgrade to Horde IMP version 2.2.8 or later." );
	script_tag( name: "summary", value: "The remote host is running at least one instance of
  Horde IMP in which the status.php3 script is vulnerable to a cross site scripting attack
  since information passed to it is not properly sanitized." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/status.php3?script=<script>vt-test</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>vt-test</script>", check_header: TRUE )){
	report = http_report_vuln_url( url: url, port: port );
	security_message( port: port, data: url );
}
exit( 0 );

