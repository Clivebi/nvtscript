if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875587" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2018-12545" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-23 18:18:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-05-03 02:08:46 +0000 (Fri, 03 May 2019)" );
	script_name( "Fedora Update for jetty FEDORA-2019-d9f867cb65" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-d9f867cb65" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CIS4LALKZNLF5X5IGNGRSKERG7FY4QG6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jetty'
  package(s) announced via the FEDORA-2019-d9f867cb65 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jetty is a 100% Java HTTP Server and Servlet Container. This means that you
do not need to configure and run a separate web server (like Apache) in order
to use Java, servlets and JSPs to generate dynamic content. Jetty is a fully
featured web server for static and dynamic content. Unlike separate
server/container solutions, this means that your web server and web
application run in the same process, without interconnection overheads
and complications. Furthermore, as a pure java component, Jetty can be simply
included in your application for demonstration, distribution or deployment.
Jetty is available on all Java supported platforms." );
	script_tag( name: "affected", value: "'jetty' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "jetty", rpm: "jetty~9.4.11~3.v20180605.fc28", rls: "FC28" ) )){
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

