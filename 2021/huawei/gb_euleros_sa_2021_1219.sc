if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1219" );
	script_cve_id( "CVE-2017-12596", "CVE-2017-9110", "CVE-2017-9111", "CVE-2017-9112", "CVE-2017-9113", "CVE-2017-9114", "CVE-2017-9115", "CVE-2017-9116" );
	script_tag( name: "creation_date", value: "2021-02-05 15:03:53 +0000 (Fri, 05 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-30 22:15:00 +0000 (Sun, 30 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for OpenEXR (EulerOS-SA-2021-1219)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1219" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1219" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'OpenEXR' package(s) announced via the EulerOS-SA-2021-1219 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In OpenEXR 2.2.0, a crafted image causes a heap-based buffer over-read in the hufDecode function in IlmImf/ImfHuf.cpp during exrmaketiled execution, it may result in denial of service or possibly unspecified other impact.(CVE-2017-12596)

In OpenEXR 2.2.0, an invalid read of size 2 in the hufDecode function in ImfHuf.cpp could cause the application to crash.(CVE-2017-9110)

In OpenEXR 2.2.0, an invalid write of size 8 in the storeSSE function in ImfOptimizedPixelReading.h could cause the application to crash or execute arbitrary code.(CVE-2017-9111)

In OpenEXR 2.2.0, an invalid read of size 1 in the getBits function in ImfHuf.cpp could cause the application to crash.(CVE-2017-9112)

In OpenEXR 2.2.0, an invalid write of size 1 in the bufferedReadPixels function in ImfInputFile.cpp could cause the application to crash or execute arbitrary code.(CVE-2017-9113)

In OpenEXR 2.2.0, an invalid read of size 1 in the refill function in ImfFastHuf.cpp could cause the application to crash.(CVE-2017-9114)

In OpenEXR 2.2.0, an invalid write of size 2 in the = operator function in half.h could cause the application to crash or execute arbitrary code.(CVE-2017-9115)

In OpenEXR 2.2.0, an invalid read of size 1 in the uncompress function in ImfZip.cpp could cause the application to crash.(CVE-2017-9116)" );
	script_tag( name: "affected", value: "'OpenEXR' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "OpenEXR-libs", rpm: "OpenEXR-libs~1.7.1~7.h3.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

