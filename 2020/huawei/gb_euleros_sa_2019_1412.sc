if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1412" );
	script_cve_id( "CVE-2018-1049", "CVE-2018-15688", "CVE-2018-16864", "CVE-2018-16865", "CVE-2019-6454" );
	script_tag( name: "creation_date", value: "2020-01-23 11:42:59 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for systemd (EulerOS-SA-2019-1412)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1412" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1412" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'systemd' package(s) announced via the EulerOS-SA-2019-1412 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An allocation of memory without limits, that could result in the stack clashing with another memory region, was discovered in systemd-journald when a program with long command line arguments calls syslog. A local attacker may use this flaw to crash systemd-journald or escalate his privileges. Versions through v240 are vulnerable.(CVE-2018-16864)

An allocation of memory without limits, that could result in the stack clashing with another memory region, was discovered in systemd-journald when many entries are sent to the journal socket. A local attacker, or a remote one if systemd-journal-remote is used, may use this flaw to crash systemd-journald or execute code with journald privileges. Versions through v240 are vulnerable.(CVE-2018-16865)

An issue was discovered in sd-bus in systemd 239. bus_process_object() in libsystemd/sd-bus/bus-objects.c allocates a variable-length stack buffer for temporarily storing the object path of incoming D-Bus messages. An unprivileged local user can exploit this by sending a specially crafted message to PID1, causing the stack pointer to jump over the stack guard pages into an unmapped memory region and trigger a denial of service (systemd PID1 crash and kernel panic).(CVE-2019-6454)

A race condition was found in systemd. This could result in automount requests not being serviced and processes using them could hang, causing denial of service.(CVE-2018-1049)

It was discovered that systemd-network does not correctly keep track of a buffer size when constructing DHCPv6 packets. This flaw may lead to an integer underflow that can be used to produce an heap-based buffer overflow. A malicious host on the same network segment as the victim's one may advertise itself as a DHCPv6 server and exploit this flaw to cause a Denial of Service or potentially gain code execution on the victim's machine.(CVE-2018-15688)" );
	script_tag( name: "affected", value: "'systemd' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "EULEROSVIRTARM64-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "libgudev1", rpm: "libgudev1~219~57.h82", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~219~57.h82", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-libs", rpm: "systemd-libs~219~57.h82", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-networkd", rpm: "systemd-networkd~219~57.h82", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-python", rpm: "systemd-python~219~57.h82", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-resolved", rpm: "systemd-resolved~219~57.h82", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysv", rpm: "systemd-sysv~219~57.h82", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

