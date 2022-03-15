CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801692" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)" );
	script_cve_id( "CVE-2010-4348", "CVE-2010-4349", "CVE-2010-4350" );
	script_bugtraq_id( 45399 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "MantisBT Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=12607" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=663230" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4983.php" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied input via the
  'db_type' parameter in 'admin/upgrade_unattended.php' that allows the
  attackers to inject arbitrary web script or HTML, obtain sensitive information
  and execute arbitrary local files." );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.2.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running MantisBT and is prone to multiple
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to inject arbitrary web script
  or HTML, obtain sensitive information and execute arbitrary local files." );
	script_tag( name: "affected", value: "MantisBT version prior to 1.2.4." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/admin/upgrade_unattended.php?db_type=<script>alert('vt-xss-test')</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert" + "\\('vt-xss-test'\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

