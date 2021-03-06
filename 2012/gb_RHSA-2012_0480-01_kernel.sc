if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2012-April/msg00012.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870586" );
	script_version( "$Revision: 14114 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-06-15 18:54:59 +0530 (Fri, 15 Jun 2012)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-1583" );
	script_xref( name: "RHSA", value: "2012:0480-01" );
	script_name( "RedHat Update for kernel RHSA-2012:0480-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_tag( name: "affected", value: "kernel on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issue:

  * A flaw in the xfrm6_tunnel_rcv() function in the Linux kernel's IPv6
  implementation could lead to a use-after-free or double free flaw in
  tunnel6_rcv(). A remote attacker could use this flaw to send
  specially-crafted packets to a target system that is using IPv6 and also
  has the xfrm6_tunnel kernel module loaded, causing it to crash.
  (CVE-2012-1583, Important)

  If you do not run applications that use xfrm6_tunnel, you can prevent the
  xfrm6_tunnel module from being loaded by creating (as the root user) a
  '/etc/modprobe.d/xfrm6_tunnel.conf' file, and adding the following line to
  it:

  blacklist xfrm6_tunnel

  This way, the xfrm6_tunnel module cannot be loaded accidentally. A reboot
  is not necessary for this change to take effect.

  This update also fixes various bugs and adds an enhancement. Documentation
  for these changes will be available shortly from the Technical Notes
  document linked to in the References section.

  Users should upgrade to these updated packages, which contain backported
  patches to correct this issue, and fix the bugs and add the enhancement
  noted in the Technical Notes. The system must be rebooted for this update
  to take effect." );
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
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE", rpm: "kernel-PAE~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE-debuginfo", rpm: "kernel-PAE-debuginfo~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE-devel", rpm: "kernel-PAE-devel~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo-common", rpm: "kernel-debuginfo-common~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.18~308.4.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

