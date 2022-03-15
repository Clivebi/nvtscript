if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852033" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-1000622" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-27 15:15:00 +0000 (Fri, 27 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:35:58 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for rust (openSUSE-SU-2018:3451-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:3451-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00068.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rust'
  package(s) announced via the openSUSE-SU-2018:3451-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rust fixes the following issues:

  - CVE-2018-1000622: rustdoc loads plugins from world writable directory
  allowing for arbitrary code execution This patch consists of requiring
  `--plugin-path` to be passed whenever `--plugin` is passed Note that
  rustdoc plugins will be removed entirely on 1.28.0 (bsc#1100691).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1279=1" );
	script_tag( name: "affected", value: "rust on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "rust", rpm: "rust~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rust-debuginfo", rpm: "rust-debuginfo~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rust-debugsource", rpm: "rust-debugsource~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rust-doc", rpm: "rust-doc~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rust-gdb", rpm: "rust-gdb~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rust-std", rpm: "rust-std~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rust-std-debuginfo", rpm: "rust-std-debuginfo~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ust-src", rpm: "ust-src~1.24.1~lp150.2.4.1", rls: "openSUSELeap15.0" ) )){
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

