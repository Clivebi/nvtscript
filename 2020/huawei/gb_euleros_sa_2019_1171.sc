if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1171" );
	script_cve_id( "CVE-2016-3189" );
	script_tag( name: "creation_date", value: "2020-01-23 11:33:33 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for bzip2 (EulerOS-SA-2019-1171)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1171" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1171" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'bzip2' package(s) announced via the EulerOS-SA-2019-1171 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A use-after-free flaw was found in bzip2recover, leading to a null pointer dereference, or a write to a closed file descriptor. An attacker could use this flaw by sending a specially crafted bzip2 file to recover and force the program to crash.(CVE-2016-3189)" );
	script_tag( name: "affected", value: "'bzip2' package(s) on Huawei EulerOS Virtualization 2.5.3." );
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
if(release == "EULEROSVIRT-2.5.3"){
	if(!isnull( res = isrpmvuln( pkg: "bzip2", rpm: "bzip2~1.0.6~14", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bzip2-devel", rpm: "bzip2-devel~1.0.6~14", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bzip2-libs", rpm: "bzip2-libs~1.0.6~14", rls: "EULEROSVIRT-2.5.3" ) )){
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

