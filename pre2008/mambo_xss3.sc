CPE = "cpe:/a:mambo-foundation:mambo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16316" );
	script_version( "$Revision: 12818 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1825" );
	script_bugtraq_id( 9890 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Mambo Site Server index.php mos_change_template XSS" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2005 David Maciejak" );
	script_dependencies( "mambo_detect.sc", "cross_site_scripting.sc" );
	script_mandatory_keys( "mambo_cms/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Upgrade at least to version 4.5 1.0.4" );
	script_tag( name: "summary", value: "An attacker may use the installed version of Mambo Site Server to
  perform a cross site scripting attack on this host." );
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
url = dir + "/index.php?mos_change_template=<script>foo</script>";
req = http_get( item: url, port: port );
resp = http_keepalive_send_recv( port: port, data: req );
if(!resp){
	exit( 0 );
}
if(IsMatchRegexp( resp, "HTTP/1\\.. 200" ) && ContainsString( resp, "<form action=\"/index.php?mos_change_template=<script>foo</script>" )){
	security_message( port );
	exit( 0 );
}
exit( 99 );

