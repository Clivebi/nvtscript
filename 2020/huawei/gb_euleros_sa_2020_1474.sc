if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1474" );
	script_cve_id( "CVE-2015-8806", "CVE-2016-4483", "CVE-2017-5969", "CVE-2019-19956" );
	script_tag( name: "creation_date", value: "2020-04-16 05:57:38 +0000 (Thu, 16 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 15:32:00 +0000 (Fri, 11 Sep 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for libxml2 (EulerOS-SA-2020-1474)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.2\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1474" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1474" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libxml2' package(s) announced via the EulerOS-SA-2020-1474 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The xmlBufAttrSerializeTxtContent function in xmlsave.c in libxml2 allows context-dependent attackers to cause a denial of service (out-of-bounds read and application crash) via a non-UTF-8 attribute value, related to serialization. NOTE: this vulnerability may be a duplicate of CVE-2016-3627.(CVE-2016-4483)

xmlParseBalancedChunkMemoryRecover in parser.c in libxml2 before 2.9.10 has a memory leak related to newDoc->oldNs.(CVE-2019-19956)

dict.c in libxml2 allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via an unexpected character immediately after the '<!DOCTYPE html' substring in a crafted HTML document.(CVE-2015-8806)

** DISPUTED ** libxml2 2.9.4, when used in recover mode, allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted XML document. NOTE: The maintainer states 'I would disagree of a CVE with the Recover parsing option which should only be used for manual recovery at least for XML parser.'(CVE-2017-5969)" );
	script_tag( name: "affected", value: "'libxml2' package(s) on Huawei EulerOS Virtualization 3.0.2.2." );
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
if(release == "EULEROSVIRT-3.0.2.2"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.9.1~6.3.h22.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.9.1~6.3.h22.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.9.1~6.3.h22.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
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

