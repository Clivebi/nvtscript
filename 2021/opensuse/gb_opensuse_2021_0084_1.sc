if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853680" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-5283" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-15 06:15:00 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:50 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for viewvc (openSUSE-SU-2021:0084-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0084-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MFA7OR2MLXELR6A6M634B47K2RIB7LYV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'viewvc'
  package(s) announced via the openSUSE-SU-2021:0084-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for viewvc fixes the following issues:

  - update to 1.1.28 (boo#1167974, CVE-2020-5283):

  * security fix: escape subdir lastmod file name (#211)

  * fix standalone.py first request failure (#195)

  * suppress stack traces (with option to show) (#140)

  * distinguish text/binary/image files by icons (#166, #175)

  * colorize alternating file content lines (#167)

  * link to the instance root from the ViewVC logo (#168)

  * display directory and root counts, too (#169)

  * fix double fault error in standalone.py (#157)

  * support timezone offsets with minutes piece (#176)" );
	script_tag( name: "affected", value: "'viewvc' package(s) on openSUSE Leap 15.1." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "viewvc", rpm: "viewvc~1.1.28~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

