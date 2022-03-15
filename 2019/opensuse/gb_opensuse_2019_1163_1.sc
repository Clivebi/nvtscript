if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852401" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-3824" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-06 02:00:54 +0000 (Sat, 06 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for ldb (openSUSE-SU-2019:1163-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1163-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00035.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ldb'
  package(s) announced via the openSUSE-SU-2019:1163-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ldb fixes the following issue:

  Security issue fixed:

  - CVE-2019-3824: Fixed an out-of-bound read vulnerability in
  ldb_wildcard_compare (bsc#1125410).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1163=1" );
	script_tag( name: "affected", value: "'ldb' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "ldb-debugsource", rpm: "ldb-debugsource~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ldb-tools", rpm: "ldb-tools~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ldb-tools-debuginfo", rpm: "ldb-tools-debuginfo~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb-devel", rpm: "libldb-devel~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1", rpm: "libldb1~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-debuginfo", rpm: "libldb1-debuginfo~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-ldb", rpm: "python-ldb~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-ldb-debuginfo", rpm: "python-ldb-debuginfo~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-ldb-devel", rpm: "python-ldb-devel~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb", rpm: "python3-ldb~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-debuginfo", rpm: "python3-ldb-debuginfo~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-devel", rpm: "python3-ldb-devel~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-32bit", rpm: "libldb1-32bit~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1-32bit-debuginfo", rpm: "libldb1-32bit-debuginfo~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-ldb-32bit", rpm: "python-ldb-32bit~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-ldb-32bit-debuginfo", rpm: "python-ldb-32bit-debuginfo~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-32bit", rpm: "python3-ldb-32bit~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ldb-32bit-debuginfo", rpm: "python3-ldb-32bit-debuginfo~1.2.3~lp150.7.2", rls: "openSUSELeap15.0" ) )){
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

