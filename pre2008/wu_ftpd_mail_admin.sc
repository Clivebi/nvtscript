CPE = "cpe:/a:washington_university:wu-ftpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14371" );
	script_version( "$Revision: 13602 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-12 13:47:59 +0100 (Tue, 12 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2003-1327" );
	script_bugtraq_id( 8668 );
	script_xref( name: "OSVDB", value: "2594" );
	script_name( "wu-ftpd MAIL_ADMIN overflow" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_dependencies( "gb_wu-ftpd_detect.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "wu-ftpd/installed" );
	script_tag( name: "summary", value: "The remote Wu-FTPd server seems to be
  vulnerable to a remote flaw." );
	script_tag( name: "insight", value: "This version fails to properly check bounds
  on a pathname when Wu-Ftpd is compiled with MAIL_ADMIN enabled resulting in a
  buffer overflow. With a specially crafted request, an attacker can possibly
  execute arbitrary code as the user Wu-Ftpd runs as (usually root) resulting
  in a loss of integrity, and/or availability.

  It should be noted that this vulnerability is not present within the default
  installation of Wu-Ftpd.

  The server must be configured using the 'MAIL_ADMIN' option to notify an
  administrator when a file has been uploaded." );
	script_tag( name: "solution", value: "Upgrade to Wu-FTPd 2.6.3 when available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(egrep( pattern: "^2\\.6\\.[012]$", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references." );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

