if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1175" );
	script_cve_id( "CVE-2020-17527", "CVE-2021-24122" );
	script_tag( name: "creation_date", value: "2021-02-02 07:45:18 +0000 (Tue, 02 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for tomcat (EulerOS-SA-2021-1175)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1175" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1175" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'tomcat' package(s) announced via the EulerOS-SA-2021-1175 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "When serving resources from a network location using the NTFS file system, Apache Tomcat versions 10.0.0-M1 to 10.0.0-M9, 9.0.0.M1 to 9.0.39, 8.5.0 to 8.5.59 and 7.0.0 to 7.0.106 were susceptible to JSP source code disclosure in some configurations. The root cause was the unexpected behaviour of the JRE API File.getCanonicalPath() which in turn was caused by the inconsistent behaviour of the Windows API (FindFirstFileW) in some circumstances.(CVE-2021-24122)

While investigating bug 64830 it was discovered that Apache Tomcat 10.0.0-M1 to 10.0.0-M9, 9.0.0-M1 to 9.0.39 and 8.5.0 to 8.5.59 could re-use an HTTP request header value from the previous stream received on an HTTP/2 connection for the request associated with the subsequent stream. While this would most likely lead to an error and the closure of the HTTP/2 connection, it is possible that information could leak between requests.(CVE-2020-17527)" );
	script_tag( name: "affected", value: "'tomcat' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~9.0.10~1.h12.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~9.0.10~1.h12.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-3.0-api", rpm: "tomcat-el-3.0-api~9.0.10~1.h12.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2.3-api", rpm: "tomcat-jsp-2.3-api~9.0.10~1.h12.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~9.0.10~1.h12.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-4.0-api", rpm: "tomcat-servlet-4.0-api~9.0.10~1.h12.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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
