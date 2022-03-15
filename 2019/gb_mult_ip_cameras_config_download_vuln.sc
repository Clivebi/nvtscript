if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142502" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-11 09:04:55 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-11 02:29:00 +0000 (Thu, 11 Jul 2019)" );
	script_cve_id( "CVE-2017-8229" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Multiple IP Cameras Configuration Download Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Multiple IP Cameras (e.g. Amcrest IPM-721S) are prone to an unauthenticated
  configuration file download vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if it is possible to access the configuration file without authentication on the target host." );
	script_tag( name: "insight", value: "The file /current_config/Sha1Account1 is accessible without authentication
  which contains unencrypted credentials." );
	script_tag( name: "impact", value: "An unauthenticated attacker may obtain sensitive information like admin
  credentials and use this for further attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/ethanhunnt/IoT_vulnerabilities/blob/master/Amcrest_sec_issues.pdf" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(!res || !ContainsString( res, "version=@WebVersion@" )){
	exit( 0 );
}
url = "/current_config/Sha1Account1";
if(http_vuln_check( port: port, url: url, pattern: "\"Password\" : \"", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

