if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2513" );
	script_cve_id( "CVE-2021-3618" );
	script_tag( name: "creation_date", value: "2021-09-28 07:08:10 +0000 (Tue, 28 Sep 2021)" );
	script_version( "2021-09-28T07:08:10+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 07:08:10 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-09-28 07:07:54 +0000 (Tue, 28 Sep 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for nginx (EulerOS-SA-2021-2513)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2513" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2513" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'nginx' package(s) announced via the EulerOS-SA-2021-2513 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ALPACA is an application layer protocol content confusion attack, exploiting TLS servers implementing different protocols but using compatible certificates, such as multi-domain or wildcard certificates. A MiTM attacker having access to victim's traffic at the TCP/IP layer can redirect traffic from one subdomain to another, resulting in a valid TLS session. This breaks the authentication of TLS and cross-protocol attacks may be possible where the behavior of one protocol service may compromise the other at the application layer.(CVE-2021-3618)" );
	script_tag( name: "affected", value: "'nginx' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "nginx", rpm: "nginx~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-all-modules", rpm: "nginx-all-modules~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-filesystem", rpm: "nginx-filesystem~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-mod-http-image-filter", rpm: "nginx-mod-http-image-filter~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-mod-http-perl", rpm: "nginx-mod-http-perl~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-mod-http-xslt-filter", rpm: "nginx-mod-http-xslt-filter~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-mod-mail", rpm: "nginx-mod-mail~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-mod-stream", rpm: "nginx-mod-stream~1.16.1~1.h4.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

