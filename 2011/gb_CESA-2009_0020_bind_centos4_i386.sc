if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-January/015552.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880895" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:0020" );
	script_cve_id( "CVE-2009-0025" );
	script_name( "CentOS Update for bind CESA-2009:0020 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "bind on CentOS 4" );
	script_tag( name: "insight", value: "BIND (Berkeley Internet Name Domain) is an implementation of the DNS
  (Domain Name System) protocols.

  A flaw was discovered in the way BIND checked the return value of the
  OpenSSL DSA_do_verify function. On systems using DNSSEC, a malicious zone
  could present a malformed DSA certificate and bypass proper certificate
  validation, allowing spoofing attacks. (CVE-2009-0025)

  For users of Red Hat Enterprise Linux 3 this update also addresses a bug
  which can cause BIND to occasionally exit with an assertion failure.

  All BIND users are advised to upgrade to the updated package, which
  contains a backported patch to resolve this issue. After installing the
  update, BIND daemon will be restarted automatically." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.2.4~30.el4_7.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-chroot", rpm: "bind-chroot~9.2.4~30.el4_7.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.2.4~30.el4_7.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.2.4~30.el4_7.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.2.4~30.el4_7.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

