if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1257" );
	script_cve_id( "CVE-2021-23239", "CVE-2021-23240", "CVE-2021-3156" );
	script_tag( name: "creation_date", value: "2021-02-05 15:06:24 +0000 (Fri, 05 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for sudo (EulerOS-SA-2021-1257)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1257" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1257" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'sudo' package(s) announced via the EulerOS-SA-2021-1257 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The sudoedit personality of Sudo before 1.9.5 may allow a local unprivileged user to perform arbitrary directory-existence tests by winning a sudo_edit.c race condition in replacing a user-controlled directory by a symlink to an arbitrary path.(CVE-2021-23239)

Sudo before 1.9.5p2 has a Heap-based Buffer Overflow, allowing privilege escalation to root via 'sudoedit -s' and a command-line argument that ends with a single backslash character.(CVE-2021-3156)

selinux_edit_copy_tfiles in sudoedit in Sudo before 1.9.5 allows a local unprivileged user to gain file ownership and escalate privileges by replacing a temporary file with a symlink to an arbitrary file target. This affects SELinux RBAC support in permissive mode. Machines without SELinux are not vulnerable.(CVE-2021-23240)" );
	script_tag( name: "affected", value: "'sudo' package(s) on Huawei EulerOS V2.0SP9." );
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
if(release == "EULEROS-2.0SP9"){
	if(!isnull( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.8.27~5.h9.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
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

