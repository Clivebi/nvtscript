if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800211" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_bugtraq_id( 31739 );
	script_cve_id( "CVE-2008-5626" );
	script_name( "XM Easy Personal FTP Server Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6741" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/xm_easy_personal/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the authenticated user execute arbitrary
  codes in the context of the application and can crash the application." );
	script_tag( name: "affected", value: "Dxmsoft, XM Easy Personal FTP Server version 5.6.0 and prior." );
	script_tag( name: "insight", value: "This flaw is due to a crafted argument to the NLST command." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running XM Easy FTP Personal FTP Server and is prone
  to Denial of Service Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "DXM's FTP Server" )){
	exit( 0 );
}
dxmVer = eregmatch( pattern: "DXM's FTP Server ([0-9.]+)", string: banner );
if(dxmVer[1]){
	if(version_is_less_equal( version: dxmVer[1], test_version: "5.6.0" )){
		security_message( port: port );
	}
}

