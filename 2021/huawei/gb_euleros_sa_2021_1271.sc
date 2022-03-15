if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1271" );
	script_cve_id( "CVE-2018-16646", "CVE-2018-18897", "CVE-2018-19060", "CVE-2018-20481", "CVE-2019-14494", "CVE-2019-7310" );
	script_tag( name: "creation_date", value: "2021-02-05 15:07:05 +0000 (Fri, 05 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 02:15:00 +0000 (Mon, 09 Nov 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for poppler (EulerOS-SA-2021-1271)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9\\-X86_64" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1271" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1271" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'poppler' package(s) announced via the EulerOS-SA-2021-1271 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Poppler 0.68.0, the Parser::getObj() function in Parser.cc may cause infinite recursion via a crafted file. A remote attacker can leverage this for a DoS attack.(CVE-2018-16646)

An issue was discovered in Poppler 0.71.0. There is a memory leak in GfxColorSpace::setDisplayProfile in GfxState.cc, as demonstrated by pdftocairo.(CVE-2018-18897)

An issue was discovered in Poppler 0.71.0. There is a NULL pointer dereference in goo/GooString.h, will lead to denial of service, as demonstrated by utils/pdfdetach.cc not validating a filename of an embedded file before constructing a save path.(CVE-2018-19060)

XRef::getEntry in XRef.cc in Poppler 0.72.0 mishandles unallocated XRef entries, which allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted PDF document, when XRefEntry::setFlag in XRef.h is called from Parser::makeStream in Parser.cc.(CVE-2018-20481)

An issue was discovered in Poppler through 0.78.0. There is a divide-by-zero error in the function SplashOutputDev::tilingPatternFill at SplashOutputDev.cc.(CVE-2019-14494)

In Poppler 0.73.0, a heap-based buffer over-read (due to an integer signedness error in the XRef::getEntry function in XRef.cc) allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted PDF document, as demonstrated by pdftocairo.(CVE-2019-7310)" );
	script_tag( name: "affected", value: "'poppler' package(s) on Huawei EulerOS V2.0SP9(x86_64)." );
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
	if(!isnull( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.67.0~5.h3.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "poppler-cpp", rpm: "poppler-cpp~0.67.0~5.h3.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "poppler-help", rpm: "poppler-help~0.67.0~5.h3.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
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

