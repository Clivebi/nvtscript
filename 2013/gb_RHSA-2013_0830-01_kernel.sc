if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.870993" );
	script_version( "$Revision: 12380 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:03:48 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2013-05-17 09:49:34 +0530 (Fri, 17 May 2013)" );
	script_cve_id( "CVE-2013-2094" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "RedHat Update for kernel RHSA-2013:0830-01" );
	script_xref( name: "RHSA", value: "2013:0830-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2013-May/msg00014.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issue:

  * It was found that the Red Hat Enterprise Linux 6.1 kernel update
  (RHSA-2011:0542) introduced an integer conversion issue in the Linux
  kernel's Performance Events implementation. This led to a user-supplied
  index into the perf_swevent_enabled array not being validated properly,
  resulting in out-of-bounds kernel memory access. A local, unprivileged user
  could use this flaw to escalate their privileges. (CVE-2013-2094,
  Important)

  A public exploit that affects Red Hat Enterprise Linux 6 is available.

  Refer to Red Hat Knowledge Solution 373743, linked to in the References,
  for further information and mitigation instructions for users who are
  unable to immediately apply this update.

  Users should upgrade to these updated packages, which contain a backported
  patch to correct this issue. The system must be rebooted for this update to
  take effect.

  4. Solution:

  Before applying this update, make sure all previously-released errata
  relevant to your system have been applied.

  This update is available via the Red Hat Network. Details on how to
  use the Red Hat Network to apply this update are available at the references.

  To install kernel packages manually, use rpm -ivh [package]. Do not
  use rpm -Uvh as that will remove the running kernel binaries from
  your system. You may use rpm -e to remove old kernels after
  determining that the new kernel functions properly on your system.

  5. Bugs fixed:

  962792 - CVE-2013-2094 kernel: perf_swevent_enabled array out-of-bound access

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
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo-common-i686", rpm: "kernel-debuginfo-common-i686~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf", rpm: "perf~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf-debuginfo", rpm: "perf-debuginfo~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf-debuginfo", rpm: "python-perf-debuginfo~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo-common-x86_64", rpm: "kernel-debuginfo-common-x86_64~2.6.32~358.6.2.el6", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

