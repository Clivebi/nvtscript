CPE = "cpe:/a:theforeman:foreman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112895" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-09 13:51:11 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 16:48:00 +0000 (Thu, 10 Jun 2021)" );
	script_cve_id( "CVE-2021-3469" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Foreman < 2.3.4 Improper Authorization Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foreman_detect.sc" );
	script_mandatory_keys( "foreman/installed" );
	script_tag( name: "summary", value: "Foreman is prone to an improper authorization handling flaw." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The SmartProxyAuth of the Foreman allows controllers to
  authenticate certain requests based on the client certificate. As Puppet CA will consider
  subject alternative names (SANs) from a certificate along with Common name (CN), Puppet CA
  will sign the certificate with SANs pointing at DNS names of the already existing certificate." );
	script_tag( name: "impact", value: "An authenticated attacker can obtain a new certificate by
  crafting a Certificate Signing Request (CSR) made up with CN & SSNs and will then be able to
  impersonate the foreman-proxy to accept the request." );
	script_tag( name: "affected", value: "Foreman prior to version 2.3.4." );
	script_tag( name: "solution", value: "Update to version 2.3.4 or later." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1943630" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "2.3.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.3.4", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

