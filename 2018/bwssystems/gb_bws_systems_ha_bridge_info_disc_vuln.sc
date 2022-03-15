CPE = "cpe:/h:bws_systems:ha_bridge";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813627" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2018-12923" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-16 13:13:00 +0000 (Wed, 16 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-07-03 12:50:41 +0530 (Tue, 03 Jul 2018)" );
	script_name( "BWS Systems HA-Bridge '#!/system' URI Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running BWS Systems HA-Bridge
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check if response is disclosing sensitive information or not." );
	script_tag( name: "insight", value: "The flaw is due to improper access control
  mechanism in the '#!/system' URI." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "BWS Systems HA-Bridge." );
	script_tag( name: "solution", value: "No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "https://www.seebug.org/vuldb/ssvid-97373" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "gb_bws_systems_ha_bridge_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "BWSSystems/HA/Bridge/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!bmsPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: bmsPort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/system/settings";
#check
#http_vuln_check( port: bmsPort, url: url, check_header: TRUE, pattern: "configfile\":", "serverport\":[0-9]+", extra_check: make_list( "upnpdevicedb\":",
#
if(http_vuln_check( port: bmsPort, url: url, check_header: TRUE, pattern: "configfile\":", extra_check: make_list( "upnpdevicedb\":",
	 "numberoflogmessages\":" ) )){
	report = http_report_vuln_url( port: bmsPort, url: url );
	security_message( port: bmsPort, data: report );
	exit( 0 );
}
exit( 0 );

