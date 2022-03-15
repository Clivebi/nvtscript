if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108560" );
	script_version( "2021-04-16T08:49:36+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 08:49:36 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-03-16 08:57:17 +0100 (Sat, 16 Mar 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Report outdated / end-of-life Scan Engine / Environment (local)" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "summary", value: "This script checks and reports an outdated or end-of-life scan
  engine for the following environments:

  - Greenbone Source Edition (GSE)

  - Greenbone Security Manager TRIAL (formerly Greenbone Community Edition (GCE))

  used for this scan.

  NOTE: While this is not, in and of itself, a security vulnerability, a severity is reported to
  make you aware of a possible decreased scan coverage or missing detection of vulnerabilities on
  the target due to e.g.:

  - missing functionalities

  - missing bugfixes

  - incompatibilities within the feed" );
	script_tag( name: "solution", value: "Update to the latest available stable release for your scan
  environment. Please check the references for more information. If you're using packages provided
  by your Linux distribution please contact the maintainer of the used distribution / repository and
  request updated packages.

  If you want to accept the risk of a possible decreased scan coverage or missing detection of
  vulnerabilities on the target you can set a global override for this script as described in the
  linked GSM manual." );
	script_xref( name: "URL", value: "https://www.greenbone.net/en/testnow/" );
	script_xref( name: "URL", value: "https://community.greenbone.net/t/gvm-9-end-of-life-initial-release-2017-03-07/211" );
	script_xref( name: "URL", value: "https://community.greenbone.net/t/gvm-10-end-of-life-initial-release-2019-04-05/208" );
	script_xref( name: "URL", value: "https://community.greenbone.net/t/gvm-11-end-of-life-initial-release-2019-10-14/3674" );
	script_xref( name: "URL", value: "https://community.greenbone.net/t/gvm-20-08-stable-initial-release-2020-08-12/6312" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-20.08/en/reports.html#creating-an-override" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("misc_func.inc.sc");
expected_gsm_trial_ver = "20.08.8";
expected_libs_ver1 = "20.8.1";
if( gos_vers = get_local_gos_version() ){
	if(version_is_less( version: gos_vers, test_version: expected_gsm_trial_ver )){
		report = "Installed GSM TRIAL / GCE version:  " + gos_vers + "\n";
		report += "Latest available GSM TRIAL version: " + expected_gsm_trial_ver + "\n";
		report += "Reference URL:                      https://www.greenbone.net/en/testnow/";
		security_message( port: 0, data: report );
	}
}
else {
	if(OPENVAS_VERSION && IsMatchRegexp( OPENVAS_VERSION, "^[0-9.]+" )){
		if(version_is_less( version: OPENVAS_VERSION, test_version: expected_libs_ver1 )){
			report = "Installed GVM Libraries (gvm-libs) version:        " + OPENVAS_VERSION + "\n";
			report += "Latest available GVM Libraries (gvm-libs) version: " + expected_libs_ver1 + "\n";
			report += "Reference URL(s) for the latest available version: https://community.greenbone.net/t/gvm-20-08-stable-initial-release-2020-08-12/6312";
			security_message( port: 0, data: report );
		}
	}
}
exit( 0 );

