if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800726" );
	script_version( "$Revision: 13605 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-12 14:43:31 +0100 (Tue, 12 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_bugtraq_id( 37112 );
	script_cve_id( "CVE-2009-4108" );
	script_name( "XM Easy Personal FTP Server File/Folder Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37473" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54400" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/508049/100/0/threaded" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "gb_xm_easy_personal_ftp_detect.sc" );
	script_mandatory_keys( "XM-Easy-Personal-FTP/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the authenticated user create
  recursive directories and crash the FTP Server." );
	script_tag( name: "affected", value: "Dxmsoft XM Easy Personal FTP Server version 5.8.0 and prior." );
	script_tag( name: "insight", value: "This flaw is due to improper validation check while creating
  recursive directories by an authenticated user inside the root folder of the FTP server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running XM Easy Personal FTP Server and is prone
  to Denial of Service Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("version_func.inc.sc");
xmFTPVer = get_kb_item( "XM-Easy-Personal-FTP/Ver" );
if(xmFTPVer != NULL){
	if(version_is_less_equal( version: xmFTPVer, test_version: "5.8.0" )){
		security_message( port: 0 );
	}
}

