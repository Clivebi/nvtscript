if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1260" );
	script_cve_id( "CVE-2020-14346", "CVE-2020-14361", "CVE-2020-14362" );
	script_tag( name: "creation_date", value: "2021-02-05 15:06:30 +0000 (Fri, 05 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-09 17:15:00 +0000 (Wed, 09 Dec 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2021-1260)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1260" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1260" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'xorg-x11-server' package(s) announced via the EulerOS-SA-2021-1260 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in xorg-x11-server before 1.20.9. An integer underflow in the X input extension protocol decoding in the X server may lead to arbitrary access of memory contents. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-14346)

A flaw was found in X.Org Server before xorg-x11-server 1.20.9. An Integer underflow leading to heap-buffer overflow may lead to a privilege escalation vulnerability. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-14361)

A flaw was found in X.Org Server before xorg-x11-server 1.20.9. An Integer underflow leading to heap-buffer overflow may lead to a privilege escalation vulnerability. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-14362)" );
	script_tag( name: "affected", value: "'xorg-x11-server' package(s) on Huawei EulerOS V2.0SP9." );
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
if(release == "EULEROS-2.0SP9"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-help", rpm: "xorg-x11-server-help~1.20.6~5.h4.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
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
