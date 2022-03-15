if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103521" );
	script_bugtraq_id( 54476 );
	script_version( "2021-08-27T12:01:24+0000" );
	script_cve_id( "CVE-2013-1594", "CVE-2013-1595", "CVE-2013-1596", "CVE-2013-1597", "CVE-2013-1598" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "Vivotek Network Cameras Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54476" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-31 18:57:00 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-07-17 14:10:13 +0200 (Tue, 17 Jul 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Vivotek Network Cameras are prone to an information-disclosure
vulnerability." );
	script_tag( name: "impact", value: "Successful exploits will allow a remote attacker to gain access
to sensitive information. Information obtained will aid in
further attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/cgi-bin/admin/getparam.cgi";
if(http_vuln_check( port: port, url: url, pattern: "system_hostname" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

