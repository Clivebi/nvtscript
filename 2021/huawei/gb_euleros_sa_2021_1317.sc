if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1317" );
	script_cve_id( "CVE-2016-4356", "CVE-2016-4574", "CVE-2016-4579" );
	script_tag( name: "creation_date", value: "2021-02-22 08:37:57 +0000 (Mon, 22 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-29 13:49:00 +0000 (Fri, 29 Nov 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for libksba (EulerOS-SA-2021-1317)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1317" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1317" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libksba' package(s) announced via the EulerOS-SA-2021-1317 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The append_utf8_value function in the DN decoder (dn.c) in Libksba before 1.3.3 allows remote attackers to cause a denial of service (out-of-bounds read) by clearing the high bit of the byte after invalid utf-8 encoded data.(CVE-2016-4356)

Off-by-one error in the append_utf8_value function in the DN decoder (dn.c) in Libksba before 1.3.4 allows remote attackers to cause a denial of service (out-of-bounds read) via invalid utf-8 encoded data. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-4356.(CVE-2016-4574)

Libksba before 1.3.4 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via unspecified vectors, related to the 'returned length of the object from _ksba_ber_parse_tl.'(CVE-2016-4579)" );
	script_tag( name: "affected", value: "'libksba' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libksba", rpm: "libksba~1.3.0~5.h1", rls: "EULEROS-2.0SP2" ) )){
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

