CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804213" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_bugtraq_id( 42029 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-01-07 18:00:17 +0530 (Tue, 07 Jan 2014)" );
	script_name( "TYPO3 Frontend Open Redirection Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct phishing
attacks." );
	script_tag( name: "vuldetect", value: "Send a Crafted HTTP GET request and check whether it is able to get sensitive
information." );
	script_tag( name: "insight", value: "An error exists in Frontend Login, which fails to sanitize 'redirect_url'
parameter properly" );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.2.13, 4.3.4, 4.4.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to open redirection
vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version before 4.2.13 and below, 4.3.0 to 4.3.3 and 4.4.0" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40742/" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2010-012" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!typoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(typoLoca = get_app_location( cpe: CPE, port: typoPort )){
	url = "/typo3/?L=OUT&redirect_url=http://www.example.com";
	sndReq = http_get( item: NASLString( typoLoca, url ), port: typoPort );
	rcvRes = http_send_recv( port: typoPort, data: sndReq );
	if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 302" ) && ContainsString( rcvRes, "Expires: 0" ) && ContainsString( rcvRes, "Location: http://www.example.com" )){
		security_message( typoPort );
		exit( 0 );
	}
}

