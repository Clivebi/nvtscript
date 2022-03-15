if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800985" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3035" );
	script_bugtraq_id( 37953 );
	script_name( "Symantec Altiris NS Key Unauthorized Access Vulnerability" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_symantec_altiris_ns_detect.sc" );
	script_mandatory_keys( "Symantec/AltirisNS/Ver", "Symantec/AltirisNS/SP" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation let attackers to access certain encrypted credentials
  and encryption keys and also execute code, obtain sensitive information, or perform actions with elevated privileges." );
	script_tag( name: "affected", value: "Symantec Altiris Notification Server versions 6.0.x before 6.0 SP3 R12." );
	script_tag( name: "insight", value: "The flaw is due to the application using a static encryption key to
  encrypt and store certain credentials." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to Symantec Altiris Notification Server 6.0 SP3 R12." );
	script_tag( name: "summary", value: "This host is installed with Symantec Altiris Notification Server
  and is prone to unauthorized access vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38356" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/55952" );
	script_xref( name: "URL", value: "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100128_00" );
	script_xref( name: "URL", value: "https://kb.altiris.com/article.asp?article=46763&p=1" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
httpPort = http_get_port( default: 80 );
sndReq = http_get( item: "/Altiris/NS/logview.asp", port: httpPort );
rcvRes = http_keepalive_send_recv( port: httpPort, data: sndReq, bodyonly: 0 );
if(( isnull( rcvRes ) ) && ( !ContainsString( rcvRes, "Altiris NS " ) )){
	exit( 0 );
}
altirisVer = get_kb_item( "Symantec/AltirisNS/Ver" );
if(!altirisVer){
	exit( 0 );
}
spVer = get_kb_item( "Symantec/AltirisNS/SP" );
if( ( spVer == NULL ) && ( IsMatchRegexp( altirisVer, "^6\\.0" ) ) ){
	if(version_is_less_equal( version: altirisVer, test_version: "6.0.6074" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
else {
	if(IsMatchRegexp( spVer, "^6\\.0" )){
		if(version_is_less( version: spVer, test_version: "6.0.1210.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

