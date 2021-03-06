if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853027" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-5188" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-12 14:09:00 +0000 (Tue, 12 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-02-05 04:01:18 +0000 (Wed, 05 Feb 2020)" );
	script_name( "openSUSE: Security Advisory for e2fsprogs (openSUSE-SU-2020:0166-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0166-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00004.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'e2fsprogs'
  package(s) announced via the openSUSE-SU-2020:0166-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for e2fsprogs fixes the following issues:

  - CVE-2019-5188: Fixed a code execution vulnerability in the directory
  rehashing functionality (bsc#1160571).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-166=1" );
	script_tag( name: "affected", value: "'e2fsprogs' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs", rpm: "e2fsprogs~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-debuginfo", rpm: "e2fsprogs-debuginfo~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-debugsource", rpm: "e2fsprogs-debugsource~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-devel", rpm: "e2fsprogs-devel~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err-devel", rpm: "libcom_err-devel~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err-devel-static", rpm: "libcom_err-devel-static~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2", rpm: "libcom_err2~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-debuginfo", rpm: "libcom_err2-debuginfo~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs-devel", rpm: "libext2fs-devel~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs-devel-static", rpm: "libext2fs-devel-static~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2", rpm: "libext2fs2~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2-debuginfo", rpm: "libext2fs2-debuginfo~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-32bit-debuginfo", rpm: "e2fsprogs-32bit-debuginfo~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err-devel-32bit", rpm: "libcom_err-devel-32bit~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-32bit", rpm: "libcom_err2-32bit~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-32bit-debuginfo", rpm: "libcom_err2-32bit-debuginfo~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs-devel-32bit", rpm: "libext2fs-devel-32bit~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2-32bit", rpm: "libext2fs2-32bit~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2-32bit-debuginfo", rpm: "libext2fs2-32bit-debuginfo~1.43.8~lp151.5.12.1", rls: "openSUSELeap15.1" ) )){
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

