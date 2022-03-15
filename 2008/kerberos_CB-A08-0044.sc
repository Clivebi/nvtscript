CPE = "cpe:/a:mit:kerberos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.90016" );
	script_version( "2021-01-22T12:19:59+0000" );
	script_tag( name: "last_modification", value: "2021-01-22 12:19:59 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)" );
	script_cve_id( "CVE-2008-0948", "CVE-2008-0947", "CVE-2008-0063", "CVE-2008-0062" );
	script_bugtraq_id( 28302, 28303 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "MIT Kerberos5 < 1.6.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_kerberos5_ssh_login_detect.sc" );
	script_mandatory_keys( "mit/kerberos5/detected" );
	script_tag( name: "solution", value: "Update to version 1.6.4 or later." );
	script_tag( name: "summary", value: "MIT Kerberos5 is affected by the vulnerabilities described in
  CVE-2008-0062, CVE-2008-0063, CVE-2008-0947 and CVE-2008-0948." );
	script_tag( name: "impact", value: "CVE-2008-0062: An unauthenticated remote attacker may cause a krb4-enabled
  KDC to crash, expose information, or execute arbitrary code. Successful exploitation of this vulnerability
  could compromise the Kerberos key database and host security on the KDC host.

  CVE-2008-0063: An unauthenticated remote attacker may cause a krb4-enabled KDC to expose information. It is
  theoretically possible for the exposed information to include secret key data on some platforms.

  CVE 2008-0947: Buffer overflow in the RPC library used by libgssrpc and kadmind in MIT Kerberos 5 (krb5) 1.4
  through 1.6.3 allows remote attackers to execute arbitrary code by triggering a large number of open file
  descriptors.

  CVE 2008-0948: Buffer overflow in the RPC library (lib/rpc/rpc_dtablesize.c) used by libgssrpc and kadmind in
  MIT Kerberos 5 (krb5) 1.2.2, and probably other versions before 1.3, when running on systems whose unistd.h does
  not define the FD_SETSIZE macro, allows remote attackers to cause a denial of service (crash) and possibly
  execute arbitrary code by triggering a large number of open file descriptors." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "1.6.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.6.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

