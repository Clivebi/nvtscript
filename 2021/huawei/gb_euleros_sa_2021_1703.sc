if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1703" );
	script_cve_id( "CVE-2017-12595", "CVE-2017-9208", "CVE-2017-9209", "CVE-2017-9210" );
	script_tag( name: "creation_date", value: "2021-03-24 06:54:41 +0000 (Wed, 24 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-08 13:29:00 +0000 (Tue, 08 May 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for qpdf (EulerOS-SA-2021-1703)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1703" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1703" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'qpdf' package(s) announced via the EulerOS-SA-2021-1703 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libqpdf.a in QPDF 6.0.0 allows remote attackers to cause a denial of service (infinite recursion and stack consumption) via a crafted PDF document, related to releaseResolved functions, aka qpdf-infiniteloop1.(CVE-2017-9208)

libqpdf.a in QPDF 6.0.0 allows remote attackers to cause a denial of service (infinite recursion and stack consumption) via a crafted PDF document, related to QPDFObjectHandle::parseInternal, aka qpdf-infiniteloop2.(CVE-2017-9209)

libqpdf.a in QPDF 6.0.0 allows remote attackers to cause a denial of service (infinite recursion and stack consumption) via a crafted PDF document, related to unparse functions, aka qpdf-infiniteloop3.(CVE-2017-9210)

The tokenizer in QPDF 6.0.0 and 7.0.b1 is recursive for arrays and dictionaries, which allows remote attackers to cause a denial of service (stack consumption and segmentation fault) or possibly have unspecified other impact via a PDF document with a deep data structure, as demonstrated by a crash in QPDFObjectHandle::parseInternal in libqpdf/QPDFObjectHandle.cc.(CVE-2017-12595)" );
	script_tag( name: "affected", value: "'qpdf' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "qpdf-libs", rpm: "qpdf-libs~5.0.1~3.h2.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

