CPE = "cpe:/a:putty:putty";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803871" );
	script_version( "2021-06-01T06:37:42+0000" );
	script_tag( name: "last_modification", value: "2021-06-01 06:37:42 +0000 (Tue, 01 Jun 2021)" );
	script_tag( name: "creation_date", value: "2013-08-21 11:16:36 +0530 (Wed, 21 Aug 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852" );
	script_bugtraq_id( 61645, 61649, 61644, 61599 );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PuTTY Multiple Integer Overflow Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_putty_portable_detect.sc" );
	script_mandatory_keys( "putty/detected" );
	script_tag( name: "summary", value: "PuTTY is prone to multiple integer overflow vulnerabilities." );
	script_tag( name: "insight", value: "Multiple Integer overflow errors due to:

  - Improper processing of public-key signatures.

  - Improper validation of DSA signatures in the 'modmul()' function
  (putty/sshbn.c)

  - Not removing sensitive data stored in the memory after it is no longer
  needed.

  - Input is not properly validated when handling negative SSH handshake
  message lengths in the getstring() function in sshrsa.c and sshdss.c." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause
  heap-based buffer overflows, resulting in a denial of service or potentially allowing
  the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PuTTY version before 0.63 on Windows" );
	script_tag( name: "solution", value: "Update to version 0.63 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54354" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q3/289" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2013/q3/291" );
	script_xref( name: "URL", value: "http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html" );
	script_xref( name: "URL", value: "http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "0.63" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.63", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

