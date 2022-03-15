if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851708" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-21 08:47:56 +0100 (Wed, 21 Feb 2018)" );
	script_cve_id( "CVE-2017-12132", "CVE-2017-8804", "CVE-2018-1000001", "CVE-2018-6485", "CVE-2018-6551" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-26 14:15:00 +0000 (Wed, 26 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for glibc (openSUSE-SU-2018:0494-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glibc fixes the following issues:

  Security issues fixed:

  - CVE-2017-8804: Fix memory leak after deserialization failure in
  xdr_bytes, xdr_string (bsc#1037930)

  - CVE-2017-12132: Reduce EDNS payload size to 1200 bytes (bsc#1051791)

  - CVE-2018-6485, CVE-2018-6551: Fix integer overflows in internal memalign
  and malloc functions (bsc#1079036)

  - CVE-2018-1000001: Avoid underflow of malloced area (bsc#1074293)

  Non security bugs fixed:

  - Release read lock after resetting timeout (bsc#1073990)

  This update was imported from the SUSE:SLE-12-SP2:Update update project." );
	script_tag( name: "affected", value: "glibc on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:0494-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-02/msg00039.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debuginfo", rpm: "glibc-debuginfo~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debugsource", rpm: "glibc-debugsource~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-debuginfo", rpm: "glibc-devel-debuginfo~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-static", rpm: "glibc-devel-static~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale", rpm: "glibc-locale~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-debuginfo", rpm: "glibc-locale-debuginfo~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile", rpm: "glibc-profile~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-extra", rpm: "glibc-extra~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-extra-debuginfo", rpm: "glibc-extra-debuginfo~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils", rpm: "glibc-utils~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-debuginfo", rpm: "glibc-utils-debuginfo~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-debugsource", rpm: "glibc-utils-debugsource~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd-debuginfo", rpm: "nscd-debuginfo~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-html", rpm: "glibc-html~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-i18ndata", rpm: "glibc-i18ndata~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-info", rpm: "glibc-info~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit", rpm: "glibc-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-debuginfo-32bit", rpm: "glibc-debuginfo-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit", rpm: "glibc-devel-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-debuginfo-32bit", rpm: "glibc-devel-debuginfo-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-static-32bit", rpm: "glibc-devel-static-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-32bit", rpm: "glibc-locale-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-debuginfo-32bit", rpm: "glibc-locale-debuginfo-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-32bit", rpm: "glibc-profile-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-32bit", rpm: "glibc-utils-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils-debuginfo-32bit", rpm: "glibc-utils-debuginfo-32bit~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-obsolete", rpm: "glibc-obsolete~2.22~13.2", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-obsolete-debuginfo", rpm: "glibc-obsolete-debuginfo~2.22~13.2", rls: "openSUSELeap42.3" ) )){
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

