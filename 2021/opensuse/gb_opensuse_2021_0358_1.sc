if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853754" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2019-25013", "CVE-2020-27618", "CVE-2020-29562", "CVE-2020-29573", "CVE-2021-3326" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-06 06:15:00 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:52 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for glibc (openSUSE-SU-2021:0358-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0358-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WMNRZB427QFJOPYP4EA4KBZOTT622NY3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the openSUSE-SU-2021:0358-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glibc fixes the following issues:

  - Fix buffer overrun in EUC-KR conversion module (CVE-2019-25013,
       bsc#1182117, BZ #24973)

  - x86: Harden printf against non-normal long double values
       (CVE-2020-29573, bsc#1179721, BZ #26649)

  - gconv: Fix assertion failure in ISO-2022-JP-3 module (CVE-2021-3326,
       bsc#1181505, BZ #27256)

  - iconv: Accept redundant shift sequences in IBM1364 (CVE-2020-27618,
       bsc#1178386, BZ #26224)

  - iconv: Fix incorrect UCS4 inner loop bounds (CVE-2020-29562,
       bsc#1179694, BZ #26923)

  - Fix parsing of /sys/devices/system/cpu/online (bsc#1180038, BZ #25859)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'glibc' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debuginfo", rpm: "glibc-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debugsource", rpm: "glibc-debugsource~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-debuginfo", rpm: "glibc-devel-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-static", rpm: "glibc-devel-static~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale", rpm: "glibc-locale~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-base", rpm: "glibc-locale-base~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-base-debuginfo", rpm: "glibc-locale-base-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile", rpm: "glibc-profile~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-extra", rpm: "glibc-extra~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-extra-debuginfo", rpm: "glibc-extra-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils", rpm: "glibc-utils~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-debuginfo", rpm: "glibc-utils-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-src-debugsource", rpm: "glibc-utils-src-debugsource~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd-debuginfo", rpm: "nscd-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit", rpm: "glibc-32bit~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit-debuginfo", rpm: "glibc-32bit-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit", rpm: "glibc-devel-32bit~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit-debuginfo", rpm: "glibc-devel-32bit-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-static-32bit", rpm: "glibc-devel-static-32bit~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-base-32bit", rpm: "glibc-locale-base-32bit~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-base-32bit-debuginfo", rpm: "glibc-locale-base-32bit-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-32bit", rpm: "glibc-profile-32bit~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-32bit", rpm: "glibc-utils-32bit~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-32bit-debuginfo", rpm: "glibc-utils-32bit-debuginfo~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-html", rpm: "glibc-html~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-i18ndata", rpm: "glibc-i18ndata~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-info", rpm: "glibc-info~2.26~lp152.26.6.1", rls: "openSUSELeap15.2" ) )){
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

