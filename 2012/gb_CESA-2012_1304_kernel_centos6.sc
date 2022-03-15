if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-September/018901.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881508" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-09-27 09:07:08 +0530 (Thu, 27 Sep 2012)" );
	script_cve_id( "CVE-2012-2313", "CVE-2012-2384", "CVE-2012-2390", "CVE-2012-3430", "CVE-2012-3552" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 11:33:00 +0000 (Fri, 31 Jul 2020)" );
	script_xref( name: "CESA", value: "2012:1304" );
	script_name( "CentOS Update for kernel CESA-2012:1304 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "kernel on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * An integer overflow flaw was found in the i915_gem_do_execbuffer()
  function in the Intel i915 driver in the Linux kernel. A local,
  unprivileged user could use this flaw to cause a denial of service. This
  issue only affected 32-bit systems. (CVE-2012-2384, Moderate)

  * A memory leak flaw was found in the way the Linux kernel's memory
  subsystem handled resource clean up in the mmap() failure path when the
  MAP_HUGETLB flag was set. A local, unprivileged user could use this flaw to
  cause a denial of service. (CVE-2012-2390, Moderate)

  * A race condition was found in the way access to inet->opt ip_options was
  synchronized in the Linux kernel's TCP/IP protocol suite implementation.
  Depending on the network facing applications running on the system, a
  remote attacker could possibly trigger this flaw to cause a denial of
  service. A local, unprivileged user could use this flaw to cause a denial
  of service regardless of the applications the system runs. (CVE-2012-3552,
  Moderate)

  * A flaw was found in the way the Linux kernel's dl2k driver, used by
  certain D-Link Gigabit Ethernet adapters, restricted IOCTLs. A local,
  unprivileged user could use this flaw to issue potentially harmful IOCTLs,
  which could cause Ethernet adapters using the dl2k driver to malfunction
  (for example, losing network connectivity). (CVE-2012-2313, Low)

  * A flaw was found in the way the msg_namelen variable in the rds_recvmsg()
  function of the Linux kernel's Reliable Datagram Sockets (RDS) protocol
  implementation was initialized. A local, unprivileged user could use this
  flaw to leak kernel stack memory to user-space. (CVE-2012-3430, Low)

  Red Hat would like to thank Hafid Lin for reporting CVE-2012-3552, and
  Stephan Mueller for reporting CVE-2012-2313. The CVE-2012-3430 issue was
  discovered by the Red Hat InfiniBand team.

  This update also fixes several bugs. Documentation for these changes will
  be available shortly from the Technical Notes document linked to in the
  References section.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues, and fix the bugs noted in the Technical
  Notes. The system must be rebooted for this update to take effect." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf", rpm: "perf~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~2.6.32~279.9.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

