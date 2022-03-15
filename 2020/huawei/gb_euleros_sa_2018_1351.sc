if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1351" );
	script_cve_id( "CVE-2018-14634" );
	script_tag( name: "creation_date", value: "2020-01-23 11:23:03 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2018-1351)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1351" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1351" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2018-1351 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An integer overflow flaw was found in the Linux kernel's create_elf_tables() function. An unprivileged local user with access to SUID (or otherwise privileged) binary could use this flaw to escalate their privileges on the system.(CVE-2018-14634)" );
	script_tag( name: "affected", value: "'kernel' package(s) on Huawei EulerOS Virtualization 2.5.2." );
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
if(release == "EULEROSVIRT-2.5.2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~514.44.5.10_97", rls: "EULEROSVIRT-2.5.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~514.44.5.10_97", rls: "EULEROSVIRT-2.5.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~514.44.5.10_97", rls: "EULEROSVIRT-2.5.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~514.44.5.10_97", rls: "EULEROSVIRT-2.5.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~514.44.5.10_97", rls: "EULEROSVIRT-2.5.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~514.44.5.10_97", rls: "EULEROSVIRT-2.5.2" ) )){
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

