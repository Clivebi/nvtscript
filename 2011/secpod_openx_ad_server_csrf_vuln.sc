CPE = "cpe:/a:openx:openx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902458" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "OpenX Ad Server Cross Site Request Forgery Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103352/openxad-xsrf.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "OpenX_detect.sc" );
	script_mandatory_keys( "openx/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain
  administrative privileges on the target application and can cause CSRF attack." );
	script_tag( name: "affected", value: "OpenX Ad Server version 2.8.7 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error in administrative interface, which
  can be exploited by remote attackers to force a logged-in administrator to perform malicious actions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running OpenX Ad Server and is prone to cross site
  request forgery vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.8.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

