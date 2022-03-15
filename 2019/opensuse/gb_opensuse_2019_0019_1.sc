if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852227" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2018-11468", "CVE-2018-12495" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-01-12 04:00:45 +0100 (Sat, 12 Jan 2019)" );
	script_name( "openSUSE: Security Advisory for discount (openSUSE-SU-2019:0019-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2019:0019-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00007.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'discount'
  package(s) announced via the openSUSE-SU-2019:0019-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for discount to version 2.2.4 fixes the following issues:

  Security issues fixed:

  - CVE-2018-11468: Fixed a heap-based buffer over-read in the
  __mkd_trim_line function from mkdio.c (boo#1094809)

  - CVE-2018-12495: Fixed a heap-based buffer over-read via a crafted file
  (boo#1098252)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-19=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-19=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-19=1" );
	script_tag( name: "affected", value: "discount on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "discount", rpm: "discount~2.2.4~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "discount-debugsource", rpm: "discount-debugsource~2.2.4~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmarkdown-devel", rpm: "libmarkdown-devel~2.2.4~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmarkdown2", rpm: "libmarkdown2~2.2.4~7.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmarkdown2-debuginfo", rpm: "libmarkdown2-debuginfo~2.2.4~7.3.1", rls: "openSUSELeap42.3" ) )){
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "discount", rpm: "discount~2.2.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "discount-debugsource", rpm: "discount-debugsource~2.2.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmarkdown-devel", rpm: "libmarkdown-devel~2.2.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmarkdown2", rpm: "libmarkdown2~2.2.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmarkdown2-debuginfo", rpm: "libmarkdown2-debuginfo~2.2.4~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

