if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1854.1" );
	script_cve_id( "CVE-2012-4412", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4788" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1854-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1854-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131854-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2013:1854-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glibc contains the following fixes:

 * Fix integer overflows in malloc (CVE-2013-4332,
bnc#839870)
 * Fix buffer overflow in glob (bnc#691365)
 * Fix buffer overflow in strcoll (CVE-2012-4412,
bnc#779320)
 * Update mount flags in (bnc#791928)
 * Fix buffer overrun in regexp matcher (CVE-2013-0242,
bnc#801246)
 * Fix memory leaks in dlopen (bnc#811979)
 * Fix stack overflow in getaddrinfo with many results
(CVE-2013-1914, bnc#813121)
 * Fix check for XEN build in glibc_post_upgrade that causes missing init re-exec (bnc#818628)
 * Don't raise UNDERFLOW in tan/tanf for small but normal argument (bnc#819347)
 * Properly cross page boundary in SSE4.2 implementation of strcmp (bnc#822210)
 * Fix robust mutex handling after fork (bnc#827811)
 * Fix missing character in IBM-943 charset (bnc#828235)
 * Fix use of alloca in gaih_inet (bnc#828637)
 * Initialize pointer guard also in static executables
(CVE-2013-4788, bnc#830268)
 * Fix readdir_r with long file names (CVE-2013-4237,
bnc#834594).
Security Issues:
 * CVE-2012-4412
>
 * CVE-2013-0242
>
 * CVE-2013-1914
>
 * CVE-2013-4237
>
 * CVE-2013-4332
>
 * CVE-2013-4788
>" );
	script_tag( name: "affected", value: "'glibc' package(s) on SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit", rpm: "glibc-32bit~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit", rpm: "glibc-devel-32bit~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-html", rpm: "glibc-html~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-i18ndata", rpm: "glibc-i18ndata~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-info", rpm: "glibc-info~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale", rpm: "glibc-locale~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-32bit", rpm: "glibc-locale-32bit~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-x86", rpm: "glibc-locale-x86~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile", rpm: "glibc-profile~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-32bit", rpm: "glibc-profile-32bit~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-x86", rpm: "glibc-profile-x86~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-x86", rpm: "glibc-x86~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.11.3~17.45.49.1", rls: "SLES11.0SP2" ) )){
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

