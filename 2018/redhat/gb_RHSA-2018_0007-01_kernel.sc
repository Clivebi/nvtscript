if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812397" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-05 23:54:03 +0100 (Fri, 05 Jan 2018)" );
	script_cve_id( "CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 17:43:00 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for kernel RHSA-2018:0007-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux
  kernel, the core of any Linux operating system. Security Fix(es): An
  industry-wide issue was found in the way many modern microprocessor designs have
  implemented speculative execution of instructions (a commonly used performance
  optimization). There are three primary variants of the issue which differ in the
  way the speculative execution can be exploited. Note: This issue is present in
  hardware and cannot be fully fixed via software update. The updated kernel
  packages provide software mitigation for this hardware issue at a cost of
  potential performance penalty. Please refer to References section for further
  information about this issue and the performance impact. In this update
  mitigations for x86-64 architecture are provided. Variant CVE-2017-5753 triggers
  the speculative execution by performing a bounds-check bypass. It relies on the
  presence of a precisely-defined instruction sequence in the privileged code as
  well as the fact that memory accesses may cause allocation into the
  microprocessor's data cache even for speculatively executed instructions that
  never actually commit (retire). As a result, an unprivileged attacker could use
  this flaw to cross the syscall boundary and read privileged memory by conducting
  targeted cache side-channel attacks. (CVE-2017-5753, Important) Variant
  CVE-2017-5715 triggers the speculative execution by utilizing branch target
  injection. It relies on the presence of a precisely-defined instruction sequence
  in the privileged code as well as the fact that memory accesses may cause
  allocation into the microprocessor's data cache even for speculatively executed
  instructions that never actually commit (retire). As a result, an unprivileged
  attacker could use this flaw to cross the syscall and guest/host boundaries and
  read privileged memory by conducting targeted cache side-channel attacks.
  (CVE-2017-5715, Important) Variant CVE-2017-5754 relies on the fact that, on
  impacted microprocessors, during speculative execution of instruction permission
  faults, exception generation triggered by a faulting access is suppressed until
  the retirement of the whole instruction block. In a combination with the fact
  that memory accesses may populate the cache even when the block is being dropped
  and never committed (executed), an unprivileged local attacker could use this
  flaw to read privileged (kernel space) memory by conducting targeted cache
  side-channel attacks. (CVE-2017-5754, Important) Note: CVE-2017-5754 affects
  Intel x86-64 microprocessors. AMD x86-64 microprocessors are not affected by
  this issue. Red Hat would like to thank Google Project Zero for reporting these
  issues." );
	script_tag( name: "affected", value: "kernel on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2018:0007-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2018-January/msg00008.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo", rpm: "kernel-debuginfo~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debuginfo-common-x86_64", rpm: "kernel-debuginfo-common-x86_64~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-debuginfo", rpm: "kernel-tools-debuginfo~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf", rpm: "perf~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf-debuginfo", rpm: "perf-debuginfo~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf-debuginfo", rpm: "python-perf-debuginfo~3.10.0~693.11.6.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

