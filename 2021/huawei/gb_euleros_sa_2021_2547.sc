if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2547" );
	script_cve_id( "CVE-2021-30465" );
	script_tag( name: "creation_date", value: "2021-09-28 07:08:10 +0000 (Tue, 28 Sep 2021)" );
	script_version( "2021-09-28T07:08:10+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 07:08:10 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-10 05:15:00 +0000 (Sat, 10 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for docker-engine (EulerOS-SA-2021-2547)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9\\-X86_64" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2547" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2547" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'docker-engine' package(s) announced via the EulerOS-SA-2021-2547 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the vulnerability, an attacker must be able to create multiple containers with a fairly specific mount configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.(CVE-2021-30465)" );
	script_tag( name: "affected", value: "'docker-engine' package(s) on Huawei EulerOS V2.0SP9(x86_64)." );
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
if(release == "EULEROS-2.0SP9-x86_64"){
	if(!isnull( res = isrpmvuln( pkg: "docker-engine", rpm: "docker-engine~18.09.0.129~1.h37.17.8.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-engine-selinux", rpm: "docker-engine-selinux~18.09.0.129~1.h37.17.8.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
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

