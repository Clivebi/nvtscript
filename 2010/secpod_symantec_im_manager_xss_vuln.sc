if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902132" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3036" );
	script_bugtraq_id( 38241 );
	script_name( "Symantec IM Manager Console Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38672" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0438" );
	script_xref( name: "URL", value: "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100218_00" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Symantec/IM/Manager" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary script code." );
	script_tag( name: "affected", value: "Symantec IM Manager version 8.3 and 8.4 before 8.4.13" );
	script_tag( name: "insight", value: "The flaw is caused due input validation error in the 'management console',
  which fails to properly filter/validate external input from non-privileged
  users with authorized access to the console." );
	script_tag( name: "solution", value: "Update to Symantec IM Manager version 8.4.13" );
	script_tag( name: "summary", value: "This host is installed with Symantec IM Manager and is prone to
  Cross Site Scripting vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.symantec.com/business/im-manager" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
httpPort = http_get_port( default: 80 );
sndReq = http_get( item: "/immanager", port: httpPort );
rcvRes = http_send_recv( port: httpPort, data: sndReq );
if(( isnull( rcvRes ) ) && ( !ContainsString( rcvRes, "Symantec :: IM Manager" ) )){
	exit( 0 );
}
imVer = get_kb_item( "Symantec/IM/Manager" );
if(!imVer){
	exit( 0 );
}
if(version_is_equal( version: imVer, test_version: "8.3" ) || version_in_range( version: imVer, test_version: "8.4", test_version2: "8.4.1361" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

