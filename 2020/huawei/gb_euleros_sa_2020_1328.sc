if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1328" );
	script_cve_id( "CVE-2018-11713" );
	script_tag( name: "creation_date", value: "2020-03-24 07:32:57 +0000 (Tue, 24 Mar 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for webkitgtk4 (EulerOS-SA-2020-1328)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1328" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1328" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'webkitgtk4' package(s) announced via the EulerOS-SA-2020-1328 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "WebCore/platform/network/soup/SocketStreamHandleImplSoup.cpp in the libsoup network backend of WebKit, as used in WebKitGTK+ prior to version 2.20.0 or without libsoup 2.62.0, unexpectedly failed to use system proxy settings for WebSocket connections. As a result, users could be deanonymized by crafted web sites via a WebSocket connection.(CVE-2018-11713)" );
	script_tag( name: "affected", value: "'webkitgtk4' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "webkitgtk4", rpm: "webkitgtk4~2.16.6~6.h9.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkitgtk4-devel", rpm: "webkitgtk4-devel~2.16.6~6.h9.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkitgtk4-jsc", rpm: "webkitgtk4-jsc~2.16.6~6.h9.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkitgtk4-jsc-devel", rpm: "webkitgtk4-jsc-devel~2.16.6~6.h9.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkitgtk4-plugin-process-gtk2", rpm: "webkitgtk4-plugin-process-gtk2~2.16.6~6.h9.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

