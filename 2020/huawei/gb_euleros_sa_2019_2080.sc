if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2080" );
	script_cve_id( "CVE-2019-0220" );
	script_tag( name: "creation_date", value: "2020-01-23 12:33:28 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for httpd (EulerOS-SA-2019-2080)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2080" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2080" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'httpd' package(s) announced via the EulerOS-SA-2019-2080 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found in Apache HTTP Server 2.4.0 to 2.4.38. When the path component of a request URL contains multiple consecutive slashes ('/'), directives such as LocationMatch and RewriteRule must account for duplicates in regular expressions while other aspects of the servers processing will implicitly collapse them.(CVE-2019-0220)" );
	script_tag( name: "affected", value: "'httpd' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "httpd", rpm: "httpd~2.4.34~8.h8.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-devel", rpm: "httpd-devel~2.4.34~8.h8.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-filesystem", rpm: "httpd-filesystem~2.4.34~8.h8.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-manual", rpm: "httpd-manual~2.4.34~8.h8.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-tools", rpm: "httpd-tools~2.4.34~8.h8.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mod_session", rpm: "mod_session~2.4.34~8.h8.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mod_ssl", rpm: "mod_ssl~2.4.34~8.h8.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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
