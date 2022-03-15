if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1242" );
	script_cve_id( "CVE-2018-16864" );
	script_tag( name: "creation_date", value: "2020-01-23 11:36:12 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for systemd (EulerOS-SA-2019-1242)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.4" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1242" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1242" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'systemd' package(s) announced via the EulerOS-SA-2019-1242 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An allocation of memory without limits, that could result in the stack clashing with another memory region, was discovered in systemd-journald when a program with long command line arguments calls syslog. A local attacker may use this flaw to crash systemd-journald or escalate privileges.(CVE-2018-16864)" );
	script_tag( name: "affected", value: "'systemd' package(s) on Huawei EulerOS Virtualization 2.5.4." );
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
if(release == "EULEROSVIRT-2.5.4"){
	if(!isnull( res = isrpmvuln( pkg: "libgudev1-devel", rpm: "libgudev1-devel~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-devel", rpm: "systemd-devel~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-libs", rpm: "systemd-libs~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-networkd", rpm: "systemd-networkd~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-python", rpm: "systemd-python~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-resolved", rpm: "systemd-resolved~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysv", rpm: "systemd-sysv~219~57.h71", rls: "EULEROSVIRT-2.5.4" ) )){
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

