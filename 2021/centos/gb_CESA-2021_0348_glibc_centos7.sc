if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883322" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2019-25013", "CVE-2020-10029", "CVE-2020-29573" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-06 06:15:00 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-04 04:00:49 +0000 (Thu, 04 Feb 2021)" );
	script_name( "CentOS: Security Advisory for glibc (CESA-2021:0348)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:0348" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-February/048257.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the CESA-2021:0348 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The glibc packages provide the standard C libraries (libc), POSIX thread
libraries (libpthread), standard math libraries (libm), and the name
service cache daemon (nscd) used by multiple programs on the system.
Without these libraries, the Linux system cannot function correctly.

Security Fix(es):

  * glibc: buffer over-read in iconv when processing invalid multi-byte input
sequences in the EUC-KR encoding (CVE-2019-25013)

  * glibc: stack corruption from crafted input in cosl, sinl, sincosl, and
tanl functions (CVE-2020-10029)

  * glibc: stack-based buffer overflow if the input to any of the printf
family of functions is an 80-bit long double with a non-canonical bit
pattern (CVE-2020-29573)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * glibc: 64bit_strstr_via_64bit_strstr_sse2_unaligned detection fails with
large device and inode numbers (BZ#1883162)

  * glibc: Performance regression in ebizzy benchmark (BZ#1889977)" );
	script_tag( name: "affected", value: "'glibc' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.17~322.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-common", rpm: "glibc-common~2.17~322.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.17~322.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-headers", rpm: "glibc-headers~2.17~322.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-static", rpm: "glibc-static~2.17~322.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-utils", rpm: "glibc-utils~2.17~322.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.17~322.el7_9", rls: "CentOS7" ) )){
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

