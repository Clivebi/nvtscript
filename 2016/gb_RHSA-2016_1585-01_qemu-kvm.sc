if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871648" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-10 05:34:42 +0200 (Wed, 10 Aug 2016)" );
	script_cve_id( "CVE-2016-5403" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for qemu-kvm RHSA-2016:1585-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "KVM (Kernel-based Virtual Machine) is a
full virtualization solution for Linux on AMD64 and Intel 64 systems. The qemu-kvm
packages provide the user-space component for running virtual machines using KVM.

Security Fix(es):

  * Quick emulator(Qemu) built with the virtio framework is vulnerable to an
unbounded memory allocation issue. It was found that a malicious guest user
could submit more requests than the virtqueue size permits. Processing a
request allocates a VirtQueueElement and therefore causes unbounded memory
allocation on the host controlled by the guest. (CVE-2016-5403)

Red Hat would like to thank hongzhenhao (Marvel Team) for reporting this
issue." );
	script_tag( name: "affected", value: "qemu-kvm on Red Hat Enterprise Linux
Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:1585-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-August/msg00013.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
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
	if(( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~0.12.1.2~2.491.el6_8.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-debuginfo", rpm: "qemu-kvm-debuginfo~0.12.1.2~2.491.el6_8.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~0.12.1.2~2.491.el6_8.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~0.12.1.2~2.491.el6_8.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~0.12.1.2~2.491.el6_8.3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

