if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0858.1" );
	script_cve_id( "CVE-2013-1914" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0858-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0858-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130858-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2013:0858-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This collective update for the GNU C library (glibc)
provides the following fixes:

 * Fix stack overflow in getaddrinfo with many results
(bnc#813121, CVE-2013-1914)
 * Fix locking in _IO_cleanup (bnc#796982)
 * Fix buffer overflow in glob (bnc#691365)
 * Fix memory leak in execve (bnc#805899)

Security Issue reference:

 * CVE-2013-1914
>" );
	script_tag( name: "affected", value: "'glibc' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-32bit", rpm: "glibc-32bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-64bit", rpm: "glibc-64bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-32bit", rpm: "glibc-devel-32bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel-64bit", rpm: "glibc-devel-64bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-html", rpm: "glibc-html~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-i18ndata", rpm: "glibc-i18ndata~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-info", rpm: "glibc-info~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale", rpm: "glibc-locale~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-32bit", rpm: "glibc-locale-32bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-64bit", rpm: "glibc-locale-64bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-locale-x86", rpm: "glibc-locale-x86~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile", rpm: "glibc-profile~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-32bit", rpm: "glibc-profile-32bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-64bit", rpm: "glibc-profile-64bit~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-profile-x86", rpm: "glibc-profile-x86~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-x86", rpm: "glibc-x86~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.4~31.109.1", rls: "SLES10.0SP4" ) )){
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

