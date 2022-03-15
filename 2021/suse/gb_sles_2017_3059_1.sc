if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.3059.1" );
	script_cve_id( "CVE-2017-12615", "CVE-2017-12616", "CVE-2017-12617", "CVE-2017-5664", "CVE-2017-7674" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:3059-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:3059-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20173059-1/" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/tomcat-7.0-doc/changelog.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2017:3059-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Apache Tomcat was updated to 7.0.82 adding features, fixing bugs and security issues.
This is another bugfix release, for full details see:
 [link moved to references] Fixed security issues:
- CVE-2017-5664: A problem in handling error pages was fixed, to avoid
 potential file overwrites during error page handling. (bsc#1042910).
- CVE-2017-7674: A CORS Filter issue could lead to client and server side
 cache poisoning (bsc#1053352)
- CVE-2017-12617: A remote code execution possibility via JSP Upload was
 fixed (bsc#1059554)
- CVE-2017-12616: An information disclosure when using VirtualDirContext
 was fixed (bsc#1059551)
- CVE-2017-12615: A Remote Code Execution via JSP Upload was fixed
 (bsc#1059554)
Non-security issues fixed:
- Fix tomcat-digest classpath error (bsc#977410)" );
	script_tag( name: "affected", value: "'tomcat' package(s) on SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-2_2-api", rpm: "tomcat-el-2_2-api~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2_2-api", rpm: "tomcat-jsp-2_2-api~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-3_0-api", rpm: "tomcat-servlet-3_0-api~7.0.82~7.16.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~7.0.82~7.16.1", rls: "SLES12.0" ) )){
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

