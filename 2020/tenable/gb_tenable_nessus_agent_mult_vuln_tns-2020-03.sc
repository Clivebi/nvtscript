CPE = "cpe:/a:tenable:nessus_agent";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107863" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2019-1551", "CVE-2020-1967" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-08-12 16:59:18 +0200 (Wed, 12 Aug 2020)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Tenable Nessus Agent < 7.6.3 Multiple Third-party Vulnerabilities (TNS-2020-03)" );
	script_tag( name: "summary", value: "Tenable Nessus Agent is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Nessus Agent leverages third-party software to help provide underlying
  functionality. One of the third-party components (OpenSSL) was found to contain multiple vulnerabilities,
  and updated versions have been made available by the providers." );
	script_tag( name: "impact", value: "Successful exploitation may lead to:

  - A buffer overflow condition (CVE-2019-1551)

  - Server or client applications may crash due to a NULL pointer dereference as a result of incorrect
  handling of the 'signature_algorithms_cert' TLS extension (CVE-2020-1967)" );
	script_tag( name: "affected", value: "Tenable Nessus Agent versions prior to version 7.6.3." );
	script_tag( name: "solution", value: "Update to Tenable Nessus Agent version 7.6.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2020-03" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20200421.txt" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_tenable_nessus_agent_detect_smb.sc" );
	script_mandatory_keys( "tenable/nessus_agent/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.6.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.6.3", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

