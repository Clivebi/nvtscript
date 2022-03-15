if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882725" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-26 06:32:15 +0200 (Fri, 26 May 2017)" );
	script_cve_id( "CVE-2016-10208", "CVE-2016-7910", "CVE-2016-8646", "CVE-2017-5986", "CVE-2017-7308" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for kernel CESA-2017:1308 centos7" );
	script_tag( name: "summary", value: "Check the version of kernel" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux
  kernel, the core of any Linux operating system. Security Fix(es): * It was found
  that the packet_set_ring() function of the Linux kernel's networking
  implementation did not properly validate certain block-size data. A local
  attacker with CAP_NET_RAW capability could use this flaw to trigger a buffer
  overflow, resulting in the crash of the system. Due to the nature of the flaw,
  privilege escalation cannot be fully ruled out. (CVE-2017-7308, Important) *
  Mounting a crafted EXT4 image read-only leads to an attacker controlled memory
  corruption and SLAB-Out-of-Bounds reads. (CVE-2016-10208, Moderate) * A flaw was
  found in the Linux kernel's implementation of seq_file where a local attacker
  could manipulate memory in the put() function pointer. This could lead to memory
  corruption and possible privileged escalation. (CVE-2016-7910, Moderate) * A
  vulnerability was found in the Linux kernel. An unprivileged local user could
  trigger oops in shash_async_export() by attempting to force the in-kernel
  hashing algorithms into decrypting an empty data set. (CVE-2016-8646, Moderate)

  * It was reported that with Linux kernel, earlier than version v4.10-rc8, an
  application may trigger a BUG_ON in sctp_wait_for_sndbuf if the socket tx buffer
  is full, a thread is waiting on it to queue more data, and meanwhile another
  thread peels off the association being used by the first thread. (CVE-2017-5986,
  Moderate) Red Hat would like to thank Igor Redko (Virtuozzo kernel team) for
  reporting CVE-2016-8646. Additional Changes: This update also fixes several bugs
  and adds various enhancements. Documentation for these changes is available from
  the Technical Notes document linked to in the References section." );
	script_tag( name: "affected", value: "kernel on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:1308" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-May/022441.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf", rpm: "perf~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~3.10.0~514.21.1.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

