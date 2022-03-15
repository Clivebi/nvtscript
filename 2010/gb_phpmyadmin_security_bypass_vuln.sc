CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801494" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)" );
	script_cve_id( "CVE-2010-4481" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "phpMyAdmin 'phpinfo.php' Security bypass Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42485" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/3238" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2010-10.php" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let the unauthenticated attackers to display
  information related to PHP." );
	script_tag( name: "affected", value: "phpMyAdmin version prior to 3.4.0-beta1." );
	script_tag( name: "insight", value: "The flaw is caused by missing authentication in the 'phpinfo.php' script
  when 'PMA_MINIMUM_COMMON' is defined. This can be exploited to gain knowledge
  of sensitive information by requesting the file directly." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin version 3.4.0-beta1 or later" );
	script_tag( name: "summary", value: "The host is running phpMyAdmin and is prone to security bypass
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
sndReq = http_get( item: NASLString( dir, "/phpinfo.php" ), port: port );
rcvRes = http_send_recv( port: port, data: sndReq );
if(ContainsString( rcvRes, ">Configuration<" ) && ContainsString( rcvRes, ">PHP Core<" ) && ContainsString( rcvRes, ">Apache Environment<" )){
	security_message( port );
	exit( 0 );
}

