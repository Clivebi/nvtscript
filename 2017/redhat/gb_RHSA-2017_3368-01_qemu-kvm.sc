if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812317" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-01 12:17:09 +0100 (Fri, 01 Dec 2017)" );
	script_cve_id( "CVE-2017-14167", "CVE-2017-15289" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for qemu-kvm RHSA-2017:3368-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kernel-based Virtual Machine (KVM) is a full
  virtualization solution for Linux on a variety of architectures. The qemu-kvm
  package provides the user-space component for running virtual machines that use
  KVM. Security Fix(es): * Quick Emulator (QEMU), compiled with the PC System
  Emulator with multiboot feature support, is vulnerable to an OOB r/w memory
  access issue. The issue could occur due to an integer overflow while loading a
  kernel image during a guest boot. A user or process could use this flaw to
  potentially achieve arbitrary code execution on a host. (CVE-2017-14167) * Quick
  emulator (QEMU), compiled with the Cirrus CLGD 54xx VGA Emulator support, is
  vulnerable to an OOB write access issue. The issue could occur while writing to
  VGA memory via mode4and5 write functions. A privileged user inside guest could
  use this flaw to crash the QEMU process resulting in Denial of service (DoS).
  (CVE-2017-15289) Red Hat would like to thank Thomas Garnier (Google.com) for
  reporting CVE-2017-14167 and Guoxiang Niu (Huawei.com) for reporting
  CVE-2017-15289." );
	script_tag( name: "affected", value: "qemu-kvm on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:3368-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-November/msg00047.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~1.5.3~141.el7_4.4", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~1.5.3~141.el7_4.4", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-common", rpm: "qemu-kvm-common~1.5.3~141.el7_4.4", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-debuginfo", rpm: "qemu-kvm-debuginfo~1.5.3~141.el7_4.4", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~1.5.3~141.el7_4.4", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

