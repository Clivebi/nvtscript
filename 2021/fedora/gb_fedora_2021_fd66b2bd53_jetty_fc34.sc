if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879500" );
	script_version( "2021-08-20T14:00:58+0000" );
	script_cve_id( "CVE-2021-28163" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 14:00:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-11 17:15:00 +0000 (Sun, 11 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-01 03:10:32 +0000 (Sat, 01 May 2021)" );
	script_name( "Fedora: Security Advisory for jetty (FEDORA-2021-fd66b2bd53)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-fd66b2bd53" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GGNKXBNRRCZTGGXPIX3VBWCF2SAM3DWS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jetty'
  package(s) announced via the FEDORA-2021-fd66b2bd53 advisory." );
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
	script_tag( name: "affected", value: "'jetty' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "jetty", rpm: "jetty~9.4.40~1.fc34", rls: "FC34" ) )){
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

