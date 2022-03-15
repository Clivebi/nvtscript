if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113548" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-10-24 11:57:55 +0200 (Thu, 24 Oct 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-15 20:41:00 +0000 (Tue, 15 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2019-17507" );
	script_name( "D-Link DIR-816 A1 1.06 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_tag( name: "summary", value: "D-Link DIR-816 A1 devices are prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to access a sensitive page without authentication." );
	script_tag( name: "insight", value: "If a user is unauthenticated, sensitive sites are served with the line
  'top.location.href = /dir_login.asp' at the top. A client could be configured to ignore that an access the page anyway." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to gain administrative access without authentication." );
	script_tag( name: "affected", value: "D-Link DIR-816 A1 firmware version 1.06.
  Other devices might also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/dahua966/Routers-vuls/blob/master/DIR-816/vuls_info.md" );
	exit( 0 );
}
CPE_PREFIX = "cpe:/o:d-link";
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
vuln_url = dir + "/version.asp";
buf = http_get_cache( item: vuln_url, port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf, "var ModemVer" )){
	report = http_report_vuln_url( url: vuln_url, port: port );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

