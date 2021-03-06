if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854057" );
	script_version( "2021-08-26T12:01:05+0000" );
	script_cve_id( "CVE-2019-3500" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-06 18:29:00 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "creation_date", value: "2021-08-11 03:02:45 +0000 (Wed, 11 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for aria2 (openSUSE-SU-2021:1125-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1125-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/X3RWOJOX6LLCQBYIEUS2KKAEEPLXW6WP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aria2'
  package(s) announced via the openSUSE-SU-2021:1125-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for aria2 fixes the following issues:

     Update to version 1.35.0:

  * Drop SSLv3.0 and TLSv1.0 and add TLSv1.3

  * TLSv1.3 support is added for GNUTLS and OpenSSL.

  * Platform: Fix compilation without deprecated OpenSSL APIs

  * Remove linux getrandom and use C++ stdlib instead

  * Don&#x27 t send Accept Metalink header if Metalink is disabled

  - Move bash completion to better location

     Update to version 1.34.0:

  * UnknownLengthPieceStorage: return piece length show something in console
       status when downloading items with unknown content length

  * Fix bug that signal handler does not work with libaria2 when
       aria2::RUN_ONCE is passed to aria2::run().

  * Retry on HTTP 502" );
	script_tag( name: "affected", value: "'aria2' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "aria2-lang", rpm: "aria2-lang~1.35.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2", rpm: "aria2~1.35.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-debuginfo", rpm: "aria2-debuginfo~1.35.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-debugsource", rpm: "aria2-debugsource~1.35.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "aria2-devel", rpm: "aria2-devel~1.35.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaria2-0", rpm: "libaria2-0~1.35.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaria2-0-debuginfo", rpm: "libaria2-0-debuginfo~1.35.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
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

