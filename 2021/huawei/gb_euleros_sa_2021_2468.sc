if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2468" );
	script_cve_id( "CVE-2021-3445" );
	script_tag( name: "creation_date", value: "2021-09-24 02:24:28 +0000 (Fri, 24 Sep 2021)" );
	script_version( "2021-09-24T02:24:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 02:24:28 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 14:58:00 +0000 (Wed, 02 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for libdnf (EulerOS-SA-2021-2468)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2468" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2468" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libdnf' package(s) announced via the EulerOS-SA-2021-2468 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in libdnf's signature verification functionality in versions before 0.60.1. This flaw allows an attacker to achieve code execution if they can alter the header information of an RPM package and then trick a user or system into installing it. The highest risk of this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2021-3445)" );
	script_tag( name: "affected", value: "'libdnf' package(s) on Huawei EulerOS V2.0SP8." );
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
if(release == "EULEROS-2.0SP8"){
	if(!isnull( res = isrpmvuln( pkg: "libdnf", rpm: "libdnf~0.22.0~8.h4.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-hawkey", rpm: "python2-hawkey~0.22.0~8.h4.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-libdnf", rpm: "python2-libdnf~0.22.0~8.h4.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-hawkey", rpm: "python3-hawkey~0.22.0~8.h4.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-libdnf", rpm: "python3-libdnf~0.22.0~8.h4.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

