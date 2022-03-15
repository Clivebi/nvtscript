CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809154" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-6515", "CVE-2016-6210" );
	script_bugtraq_id( 92212 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-08-25 18:35:09 +0530 (Thu, 25 Aug 2016)" );
	script_name( "OpenSSH Denial of Service And User Enumeration Vulnerabilities (Linux)" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_openssh_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssh/detected", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "http://www.openssh.com/txt/release-7.3" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Jul/51" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/CVE-2016-6210" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2016/08/01/2" );
	script_tag( name: "summary", value: "This host is installed with openssh and
  is prone to denial of service and user enumeration vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The auth_password function in 'auth-passwd.c' script does not limit password
    lengths for password authentication.

  - The sshd in OpenSSH, when SHA256 or SHA512 are used for user password hashing
    uses BLOWFISH hashing on a static password when the username does not exist
    and it takes much longer to calculate SHA256/SHA512 hash than BLOWFISH hash." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows
  remote attackers to cause a denial of service (crypt CPU consumption) and
  to enumerate users by leveraging the timing difference between responses
  when a large password is provided." );
	script_tag( name: "affected", value: "OpenSSH versions before 7.3 on Linux" );
	script_tag( name: "solution", value: "Upgrade to OpenSSH version 7.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

