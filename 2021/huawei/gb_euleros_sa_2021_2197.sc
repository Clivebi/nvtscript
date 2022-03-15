if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2197" );
	script_cve_id( "CVE-2021-20266", "CVE-2021-20271", "CVE-2021-3421" );
	script_tag( name: "creation_date", value: "2021-07-13 12:59:18 +0000 (Tue, 13 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for rpm (EulerOS-SA-2021-2197)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2197" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2197" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'rpm' package(s) announced via the EulerOS-SA-2021-2197 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in the RPM package in the read functionality. This flaw allows an attacker who can convince a victim to install a seemingly verifiable package or compromise an RPM repository, to cause RPM database corruption. The highest threat from this vulnerability is to data integrity. This flaw affects RPM versions before 4.17.0-alpha.(CVE-2021-3421)

A flaw was found in RPM's hdrblobInit() in lib/header.c. This flaw allows an attacker who can modify the rpmdb to cause an out-of-bounds read. The highest threat from this vulnerability is to system availability.(CVE-2021-20266)

A flaw was found in RPM's signature check functionality when reading a package file. This flaw allows an attacker who can convince a victim to install a seemingly verifiable package, whose signature header was modified, to cause RPM database corruption and execute code. The highest threat from this vulnerability is to data integrity, confidentiality, and system availability.(CVE-2021-20271)" );
	script_tag( name: "affected", value: "'rpm' package(s) on Huawei EulerOS Virtualization release 2.9.0." );
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
if(release == "EULEROSVIRT-2.9.0"){
	if(!isnull( res = isrpmvuln( pkg: "python3-rpm", rpm: "python3-rpm~4.15.1~12.h18.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm", rpm: "rpm~4.15.1~12.h18.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-libs", rpm: "rpm-libs~4.15.1~12.h18.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
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

