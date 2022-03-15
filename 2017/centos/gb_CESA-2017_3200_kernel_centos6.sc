if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882799" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-16 07:28:40 +0100 (Thu, 16 Nov 2017)" );
	script_cve_id( "CVE-2017-14106", "CVE-2017-1000111", "CVE-2017-1000112" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for kernel CESA-2017:3200 centos6" );
	script_tag( name: "summary", value: "Check the version of kernel" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

  * A race condition issue leading to a use-after-free flaw was found in the
way the raw packet sockets are implemented in the Linux kernel networking
subsystem handling synchronization. A local user able to open a raw packet
socket (requires the CAP_NET_RAW capability) could use this flaw to elevate
their privileges on the system. (CVE-2017-1000111, Important)

  * An exploitable memory corruption flaw was found in the Linux kernel. The
append path can be erroneously switched from UFO to non-UFO in
ip_ufo_append_data() when building an UFO packet with MSG_MORE option. If
unprivileged user namespaces are available, this flaw can be exploited to
gain root privileges. (CVE-2017-1000112, Important)

  * A divide-by-zero vulnerability was found in the __tcp_select_window
function in the Linux kernel. This can result in a kernel panic causing a
local denial of service. (CVE-2017-14106, Moderate)

Red Hat would like to thank Willem de Bruijn for reporting CVE-2017-1000111
and Andrey Konovalov for reporting CVE-2017-1000112.

Bug Fix(es):

  * When the operating system was booted with Red Hat Enterprise
Virtualization, and the eh_deadline sysfs parameter was set to 10s, the
Storage Area Network (SAN) issues caused eh_deadline to trigger with no
handler. Consequently, a kernel panic occurred. This update fixes the lpfc
driver, thus preventing the kernel panic under described circumstances.
(BZ#1487220)

  * When an NFS server returned the NFS4ERR_BAD_SEQID error to an OPEN
request, the open-owner was removed from the state_owners rbtree.
Consequently, NFS4 client infinite loop that required a reboot to recover
occurred. This update changes NFS4ERR_BAD_SEQID handling to leave the
open-owner in the state_owners rbtree by updating the create_time parameter
so that it looks like a new open-owner. As a result, an NFS4 client is now
able to recover without falling into the infinite recovery loop after
receiving NFS4ERR_BAD_SEQID. (BZ#1491123)

  * If an NFS client attempted to mount NFSv3 shares from an NFS server
exported directly to the client's IP address, and this NFS client had
already mounted other shares that originated from the same server but were
exported to the subnetwork which this client was part of, the auth.unix.ip
cache expiration was not handled correctly. Consequently, the client
received the 'stale file handle' errors when trying to mount the share.
This update fixes handling of the cache expiration, and the NFSv3 shares
now mount as expected without producing the 'stale file handle' errors.
(BZ#1497 ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "kernel on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:3200" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-November/022624.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf", rpm: "perf~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~2.6.32~696.16.1.el6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

