CPE = "cpe:/a:washington_university:wu-ftpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14301" );
	script_version( "$Revision: 13602 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-12 13:47:59 +0100 (Tue, 12 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-1999-1326" );
	script_xref( name: "OSVDB", value: "8718" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "wu-ftpd ABOR privilege escalation" );
	script_category( ACT_GATHER_INFO );
	script_family( "FTP" );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_dependencies( "gb_wu-ftpd_detect.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "wu-ftpd/installed" );
	script_tag( name: "summary", value: "The remote Wu-FTPd server seems to be vulnerable to a remote privilege
  escalation." );
	script_tag( name: "insight", value: "This version contains a flaw that may allow a malicious user to gain
  access to unauthorized privileges.

  Specifically, there is a flaw in the way that the server handles an ABOR command after a data connection
  has been closed. The flaw is within the dologout() function and proper exploitation will give the
  remote attacker the ability to execute arbitrary code as the 'root' user." );
	script_tag( name: "impact", value: "This flaw may lead to a loss of confidentiality and/or integrity." );
	script_tag( name: "solution", value: "Upgrade to Wu-FTPd 2.4.2 or newer." );
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
if(egrep( pattern: "^(2\\.([0-3]\\.|4\\.[01]))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

