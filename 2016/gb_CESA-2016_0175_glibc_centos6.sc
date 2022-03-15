if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882391" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-17 06:26:54 +0100 (Wed, 17 Feb 2016)" );
	script_cve_id( "CVE-2015-7547" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for glibc CESA-2016:0175 centos6" );
	script_tag( name: "summary", value: "Check the version of glibc" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The glibc packages provide the standard C
libraries (libc), POSIX thread libraries (libpthread), standard math libraries
(libm), and the Name Server Caching Daemon (nscd) used by multiple programs on
the system. Without these libraries, the Linux system cannot function correctly.

A stack-based buffer overflow was found in the way the libresolv library
performed dual A/AAAA DNS queries. A remote attacker could create a
specially crafted DNS response which could cause libresolv to crash or,
potentially, execute code with the permissions of the user running the
library. Note: this issue is only exposed when libresolv is called from the
nss_dns NSS service module. (CVE-2015-7547)

This issue was discovered by the Google Security Team and Red Hat.

This update also fixes the following bugs:

  * The dynamic loader has been enhanced to allow the loading of more shared
libraries that make use of static thread local storage. While static thread
local storage is the fastest access mechanism it may also prevent the
shared library from being loaded at all since the static storage space is a
limited and shared process-global resource. Applications which would
previously fail with 'dlopen: cannot load any more object with static TLS'
should now start up correctly. (BZ#1291270)

  * A bug in the POSIX realtime support would cause asynchronous I/O or
certain timer API calls to fail and return errors in the presence of large
thread-local storage data that exceeded PTHREAD_STACK_MIN in size
(generally 16 KiB). The bug in librt has been corrected and the impacted
APIs no longer return errors when large thread-local storage data is
present in the application. (BZ#1301625)

All glibc users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues." );
	script_tag( name: "affected", value: "glibc on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0175" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-February/021668.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.12~1.166.el6_7.7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-common", rpm: "glibc-common~2.12~1.166.el6_7.7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.12~1.166.el6_7.7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-headers", rpm: "glibc-headers~2.12~1.166.el6_7.7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-static", rpm: "glibc-static~2.12~1.166.el6_7.7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "glibc-utils", rpm: "glibc-utils~2.12~1.166.el6_7.7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.12~1.166.el6_7.7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

