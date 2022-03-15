if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-June/018678.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881107" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:09:17 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-0217", "CVE-2012-2934" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2012:0721" );
	script_name( "CentOS Update for kernel CESA-2012:0721 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "kernel on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * It was found that the Xen hypervisor implementation as shipped with Red
  Hat Enterprise Linux 5 did not properly restrict the syscall return
  addresses in the sysret return path to canonical addresses. An unprivileged
  user in a 64-bit para-virtualized guest, that is running on a 64-bit host
  that has an Intel CPU, could use this flaw to crash the host or,
  potentially, escalate their privileges, allowing them to execute arbitrary
  code at the hypervisor level. (CVE-2012-0217, Important)

  * It was found that guests could trigger a bug in earlier AMD CPUs, leading
  to a CPU hard lockup, when running on the Xen hypervisor implementation. An
  unprivileged user in a 64-bit para-virtualized guest could use this flaw to
  crash the host. Warning: After installing this update, hosts that are using
  an affected AMD CPU (refer to Red Hat Bugzilla bug #824966 for a list) will
  fail to boot. In order to boot such hosts, the new kernel parameter,
  allow_unsafe, can be used ('allow_unsafe=on'). This option should only be
  used with hosts that are running trusted guests, as setting it to 'on'
  reintroduces the flaw (allowing guests to crash the host). (CVE-2012-2934,
  Moderate)

  Note: For Red Hat Enterprise Linux guests, only privileged guest users can
  exploit the CVE-2012-0217 and CVE-2012-2934 issues.

  Red Hat would like to thank the Xen project for reporting these issues.
  Upstream acknowledges Rafal Wojtczuk as the original reporter of
  CVE-2012-0217.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE", rpm: "kernel-PAE~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE-devel", rpm: "kernel-PAE-devel~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~2.6.18~308.8.2.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

