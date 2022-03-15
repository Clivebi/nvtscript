if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-April/017347.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881428" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:50:51 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2010-4526" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_xref( name: "CESA", value: "2011:0163" );
	script_name( "CentOS Update for kernel CESA-2011:0163 centos5 x86_64" );
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

  This update fixes the following security issue:

  * A flaw was found in the sctp_icmp_proto_unreachable() function in the
  Linux kernel's Stream Control Transmission Protocol (SCTP) implementation.
  A remote attacker could use this flaw to cause a denial of service.
  (CVE-2010-4526, Important)

  This update also fixes the following bugs:

  * Due to an off-by-one error, gfs2_grow failed to take the very last 'rgrp'
  parameter into account when adding up the new free space. With this update,
  the GFS2 kernel properly counts all the new resource groups and fixes the
  'statfs' file correctly. (BZ#666792)

  * Prior to this update, a multi-threaded application, which invoked
  popen(3) internally, could cause a thread stall by FILE lock corruption.
  The application program waited for a FILE lock in glibc, but the lock
  seemed to be corrupted, which was caused by a race condition in the COW
  (Copy On Write) logic. With this update, the race condition was corrected
  and FILE lock corruption no longer occurs. (BZ#667050)

  * If an error occurred during I/O, the SCSI driver reset the 'megaraid_sas'
  controller to restore it to normal state. However, on Red Hat Enterprise
  Linux 5, the waiting time to allow a full reset completion for the
  'megaraid_sas' controller was too short. The driver incorrectly recognized
  the controller as stalled, and, as a result, the system stalled as well.
  With this update, more time is given to the controller to properly restart,
  thus, the controller operates as expected after being reset. (BZ#667141)

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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~2.6.18~238.1.1.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

