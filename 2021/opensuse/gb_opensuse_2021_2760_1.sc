if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854071" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_cve_id( "CVE-2021-3672" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-18 03:02:51 +0000 (Wed, 18 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for c-ares (openSUSE-SU-2021:2760-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2760-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4F2ZKNNMGENSNMAS5CDHA3CDDRAXF3AQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'c-ares'
  package(s) announced via the openSUSE-SU-2021:2760-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for c-ares fixes the following issues:

     Version update to git snapshot 1.17.1+20200724:

  - CVE-2021-3672: fixed missing input validation on hostnames returned by
       DNS servers (bsc#1188881)

  - If ares_getaddrinfo() was terminated by an ares_destroy(), it would
       cause crash

  - Crash in sortaddrinfo() if the list size equals 0 due to an unexpected
       DNS response

  - Expand number of escaped characters in DNS replies as per RFC1035 5.1 to
       prevent spoofing

  - Use unbuffered /dev/urandom for random data to prevent early startup
       performance issues" );
	script_tag( name: "affected", value: "'c-ares' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "c-ares-debugsource", rpm: "c-ares-debugsource~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "c-ares-devel", rpm: "c-ares-devel~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "c-ares-utils", rpm: "c-ares-utils~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "c-ares-utils-debuginfo", rpm: "c-ares-utils-debuginfo~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcares2", rpm: "libcares2~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcares2-debuginfo", rpm: "libcares2-debuginfo~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcares2-32bit", rpm: "libcares2-32bit~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcares2-32bit-debuginfo", rpm: "libcares2-32bit-debuginfo~1.17.1+20200724~3.14.1", rls: "openSUSELeap15.3" ) )){
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

