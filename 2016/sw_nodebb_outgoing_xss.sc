CPE = "cpe:/a:nodebb:nodebb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111102" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-05-07 16:00:00 +0200 (Sat, 07 May 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "NodeBB 'outgoing' Controller Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "sw_nodebb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "NodeBB/installed" );
	script_xref( name: "URL", value: "https://cxsecurity.com/issue/WLB-2015090182" );
	script_tag( name: "summary", value: "This host is running NodeBB and is prone to a refclected Cross Site Scripting
  vulnerability." );
	script_tag( name: "impact", value: "Exploiting this vulnerability may allow an attacker to perform cross-site scripting attacks on unsuspecting users
  in the context of the affected website. As a result, the attacker may be able to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "NodeBB version prior to 0.8.0" );
	script_tag( name: "solution", value: "Update your NodeBB to a non-affected version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
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
url = dir + "/outgoing?url=<script>alert('XSS')</script>";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('XSS'\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

