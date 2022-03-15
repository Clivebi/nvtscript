if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100452" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-20 10:52:14 +0100 (Wed, 20 Jan 2010)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0359" );
	script_bugtraq_id( 37829 );
	script_name( "Zeus Web Server 'SSL2_CLIENT_HELLO' Remote Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37829" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zeus/banner" );
	script_tag( name: "summary", value: "Zeus Web Server is prone to a buffer-overflow vulnerability because
  the application fails to perform adequate boundary checks on user-supplied data." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code within the
  context of the affected application. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Versions prior to Zeus Web Server 4.3r5 are vulnerable." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Zeus/" )){
	exit( 0 );
}
version = eregmatch( pattern: "Server: Zeus/([0-9.]+[r0-9]*)", string: banner );
if(isnull( version[1] )){
	exit( 0 );
}
if(version_is_less( version: version[1], test_version: "4.3r5" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

