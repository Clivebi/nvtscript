CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801994" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)" );
	script_cve_id( "CVE-2011-3646" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "phpMyAdmin js_frame Parameter Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.auscert.org.au/render.html?it=14975" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Oct/690" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=746882" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2011-15.php" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "phpMyAdmin version 3.4.5 and prior" );
	script_tag( name: "insight", value: "The flaw is due to insufficient input validation in 'js_frame'
  parameter in 'phpmyadmin.css.php', which allows attackers to disclose
  information that could be used in further attacks." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin 3.4.6 or Apply the patch from the referenced advisory." );
	script_xref( name: "URL", value: "http://phpmyadmin.git.sourceforge.net/git/gitweb.cgi?p=phpmyadmin/phpmyadmin;a=commitdiff;h=d35cba980893aa6e6455fd6e6f14f3e3f1204c52" );
	script_tag( name: "summary", value: "The host is running phpMyAdmin and is prone to information
  disclosure vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(dir = get_app_location( cpe: CPE, port: port )){
	url = dir + "/phpmyadmin.css.php?js_frame[]=right";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "Cannot modify header information.*/phpmyadmin.css.php" )){
		security_message( port );
	}
}

