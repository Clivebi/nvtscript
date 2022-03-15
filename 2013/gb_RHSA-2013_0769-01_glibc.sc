if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.870985" );
	script_version( "$Revision: 12380 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:03:48 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-04-25 10:17:44 +0530 (Thu, 25 Apr 2013)" );
	script_cve_id( "CVE-2013-0242", "CVE-2013-1914" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "RedHat Update for glibc RHSA-2013:0769-01" );
	script_xref( name: "RHSA", value: "2013:0769-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-April/msg00034.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_tag( name: "affected", value: "glibc on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The glibc packages provide the standard C libraries (libc), POSIX thread
  libraries (libpthread), standard math libraries (libm), and the Name Server
  Caching Daemon (nscd) used by multiple programs on the system. Without
  these libraries, the Linux system cannot function correctly.

  It was found that getaddrinfo() did not limit the amount of stack memory
  used during name resolution. An attacker able to make an application
  resolve an attacker-controlled hostname or IP address could possibly cause
  the application to exhaust all stack memory and crash. (CVE-2013-1914)

  A flaw was found in the regular expression matching routines that process
  multibyte character input. If an application utilized the glibc regular
  expression matching mechanism, an attacker could provide specially-crafted
  input that, when processed, would cause the application to crash.
  (CVE-2013-0242)

  This update also fixes the following bugs:

  * The improvements RHSA-2012:1207 made to the accuracy of floating point
  functions in the math library caused performance regressions for those
  functions. The performance regressions were analyzed and a fix was applied
  that retains the current accuracy but reduces the performance penalty to
  acceptable levels. Refer to Red Hat Knowledge solution 229993, linked
  to in the References, for further information. (BZ#950535)

  * It was possible that a memory location freed by the localization code
  could be accessed immediately after, resulting in a crash. The fix ensures
  that the application does not crash by avoiding the invalid memory access.
  (BZ#951493)

  Users of glibc are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.

  4. Solution:

  Before applying this update, make sure all previously-released errata
  relevant to your system have been applied.

  This update is available via the Red Hat Network. Details on how to
  use the Red Hat Network to apply this update are available at the references.

  5. Bugs fixed:

  905874 - CVE-2013-0242 glibc: Buffer overrun (DoS) in regexp matcher by
           processing multibyte characters
  947882 - CVE-2013-1914 glibc: Stack (frame) overflow in getaddrinfo()
           when processing entry mapping to long list of address structures

  6. Package List:

  Red Hat Enterprise Linux Deskt ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://access.redhat.com/knowledge/articles/11258" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-common", rpm: "glibc-common~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-debuginfo", rpm: "glibc-debuginfo~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-debuginfo-common", rpm: "glibc-debuginfo-common~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-headers", rpm: "glibc-headers~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-utils", rpm: "glibc-utils~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.5~107.el5_9.4", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

