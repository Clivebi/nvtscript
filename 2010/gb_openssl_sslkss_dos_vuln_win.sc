CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800490" );
	script_version( "2021-06-30T11:32:25+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:32:25 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0433" );
	script_name( "OpenSSL 'kssl_keytab_is_available()' DoS Vulnerability - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2010/q1/175" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=569774" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=567711" );
	script_xref( name: "URL", value: "http://permalink.gmane.org/gmane.comp.security.oss.general/2636" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to cause DoS
  conditions." );
	script_tag( name: "affected", value: "OpenSSL version prior to 0.9.8n." );
	script_tag( name: "insight", value: "The flaw is due to error in 'kssl_keytab_is_available()'
  function in 'ssl/kssl.c' which does not check a certain return value when Kerberos is enabled.
  This allows NULL pointer dereference and daemon crash via SSL cipher negotiation." );
	script_tag( name: "solution", value: "Update to version 0.9.8n or later." );
	script_tag( name: "summary", value: "OpenSSL is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "0.9.8n" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "0.9.8n", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

