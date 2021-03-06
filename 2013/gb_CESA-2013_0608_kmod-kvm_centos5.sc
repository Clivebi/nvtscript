if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019272.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881678" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-12 10:02:32 +0530 (Tue, 12 Mar 2013)" );
	script_cve_id( "CVE-2012-6075" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2013:0608" );
	script_name( "CentOS Update for kmod-kvm CESA-2013:0608 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kmod-kvm'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "kmod-kvm on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module built for
  the standard Red Hat Enterprise Linux kernel.

  A flaw was found in the way QEMU-KVM emulated the e1000 network interface
  card when the host was configured to accept jumbo network frames, and a
  guest using the e1000 emulated driver was not. A remote attacker could use
  this flaw to crash the guest or, potentially, execute arbitrary code with
  root privileges in the guest. (CVE-2012-6075)

  All users of kvm are advised to upgrade to these updated packages, which
  contain backported patches to correct this issue. Note that the procedure
  in the Solution section must be performed before this update will take
  effect." );
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
	if(( res = isrpmvuln( pkg: "kmod-kvm", rpm: "kmod-kvm~83~262.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-kvm-debug", rpm: "kmod-kvm-debug~83~262.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kvm", rpm: "kvm~83~262.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kvm-qemu-img", rpm: "kvm-qemu-img~83~262.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kvm-tools", rpm: "kvm-tools~83~262.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

