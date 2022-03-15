CPE = "cpe:/a:freenas:freenas";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100912" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2010-11-19 13:40:50 +0100 (Fri, 19 Nov 2010)" );
	script_bugtraq_id( 44974 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "FreeNAS Remote Shell Command Execution Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44974" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/freenas/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_freenas_detect.sc" );
	script_mandatory_keys( "freenas/detected" );
	script_tag( name: "summary", value: "FreeNAS is prone to a shell-command-execution vulnerability because the
application fails to properly sanitize user-supplied input.

An attacker can exploit the remote shell-command-execution issue to execute arbitrary shell commands in the
context of the webserver process.

FreeNAS versions prior to 0.7.2 rev.5543 are vulnerable." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/exec_raw.php?cmd=id";
if(http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+.*" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

