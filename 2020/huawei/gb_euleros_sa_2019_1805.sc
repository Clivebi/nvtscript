if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1805" );
	script_cve_id( "CVE-2016-5180", "CVE-2017-1000381" );
	script_tag( name: "creation_date", value: "2020-01-23 12:23:26 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for c-ares (EulerOS-SA-2019-1805)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1805" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1805" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'c-ares' package(s) announced via the EulerOS-SA-2019-1805 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found in c-ares. A hostname with an escaped trailing dot (such as 'hello\\.') would have its size calculated incorrectly, leading to a single byte written beyond the end of a buffer on the heap. An attacker able to provide such a hostname to an application using c-ares, could potentially cause that application to crash.(CVE-2016-5180)

The c-ares function `ares_parse_naptr_reply()`, which is used for parsing NAPTR responses, could be triggered to read memory outside of the given input buffer if the passed in DNS response packet was crafted in a particular way.(CVE-2017-1000381)" );
	script_tag( name: "affected", value: "'c-ares' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "c-ares", rpm: "c-ares~1.10.0~3.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "c-ares-devel", rpm: "c-ares-devel~1.10.0~3.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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
