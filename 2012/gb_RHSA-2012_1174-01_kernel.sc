if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2012-August/msg00018.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870812" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-24 09:55:24 +0530 (Fri, 24 Aug 2012)" );
	script_cve_id( "CVE-2012-2313" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:P" );
	script_xref( name: "RHSA", value: "2012:1174-01" );
	script_name( "RedHat Update for kernel RHSA-2012:1174-01" );
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

  * A flaw was found in the way the Linux kernel's dl2k driver, used by
  certain D-Link Gigabit Ethernet adapters, restricted IOCTLs. A local,
  unprivileged user could use this flaw to issue potentially harmful IOCTLs,
  which could cause Ethernet adapters using the dl2k driver to malfunction
  (for example, losing network connectivity). (CVE-2012-2313, Low)

  Red Hat would like to thank Stephan Mueller for reporting this issue.

  This update also fixes several bugs. Documentation for these changes will
  be available shortly from the Technical Notes document linked to in the
  References section.

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
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE", rpm: "kernel-PAE~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE-debuginfo", rpm: "kernel-PAE-debuginfo~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE-devel", rpm: "kernel-PAE-devel~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo-common", rpm: "kernel-debuginfo-common~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.18~308.13.1.el5", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

