CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813887" );
	script_version( "2021-05-28T07:06:21+0000" );
	script_cve_id( "CVE-2018-15919" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-28 07:06:21 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-07 16:29:00 +0000 (Thu, 07 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-09-05 13:12:09 +0530 (Wed, 05 Sep 2018)" );
	script_name( "OpenSSH 'auth2-gss.c' User Enumeration Vulnerability - Windows" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssh/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://bugzilla.novell.com/show_bug.cgi?id=1106163" );
	script_xref( name: "URL", value: "https://seclists.org/oss-sec/2018/q3/180" );
	script_tag( name: "summary", value: "OpenSSH is prone to a user enumeration vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the 'auth-gss2.c' source code file of the
  affected software and is due to insufficient validation of an authentication request packet when
  the Guide Star Server II (GSS2) component is used on an affected system." );
	script_tag( name: "impact", value: "Successfully exploitation will allow a remote attacker to harvest
  valid user accounts, which may aid in brute-force attacks." );
	script_tag( name: "affected", value: "OpenSSH version 5.9 through 7.8." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(( revcomp( a: vers, b: "7.8p1" ) <= 0 ) && ( revcomp( a: vers, b: "5.9" ) >= 0 )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

