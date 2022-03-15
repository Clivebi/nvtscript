CPE = "cpe:/a:websense:triton";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106003" );
	script_version( "$Revision: 11291 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 16:48:41 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2015-06-04 11:08:10 +0700 (Thu, 04 Jun 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2015-2748" );
	script_bugtraq_id( 73241 );
	script_name( "Websense Triton File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_websense_triton_detect.sc" );
	script_mandatory_keys( "websense_triton/installed" );
	script_tag( name: "summary", value: "Websense Triton is vulnerable to a file disclosure
vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check
the response" );
	script_tag( name: "insight", value: "The Apache server of Websense Data Security has mapped
the explorer_wse path to a folder used by Websense for storing generated reports. No access
control is enforced on this folder. Files stored in the folder are accessible to unauthenticated user." );
	script_tag( name: "impact", value: "An attacker can abuse this issue to download any file exposed
by this path, including security reports and Websense Explorer configuration files." );
	script_tag( name: "affected", value: "Websense Triton v7.8.3 and v7.7" );
	script_tag( name: "solution", value: "Update to version 8.0 or later." );
	script_xref( name: "URL", value: "https://www.securify.nl/advisory/SFY20140909/missing_access_control_on_websense_explorer_web_folder.html" );
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
url = dir + "/explorer_wse/websense.ini";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "[Policy Server]", extra_check: make_list( "[Communication Ports]",
	 "[UserService]",
	 "[EIMServer]" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

