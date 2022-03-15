if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876556" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2019-0221", "CVE-2019-0199", "CVE-2018-11784" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-28 21:29:00 +0000 (Tue, 28 May 2019)" );
	script_tag( name: "creation_date", value: "2019-07-05 02:21:34 +0000 (Fri, 05 Jul 2019)" );
	script_name( "Fedora Update for tomcat FEDORA-2019-d66febb5df" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-d66febb5df" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NPHQEL5AQ6LZSZD2Y6TYZ4RC3WI7NXJ3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'tomcat' package(s) announced via the FEDORA-2019-d66febb5df advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Tomcat is the servlet container that is used
  in the official Reference Implementation for the Java Servlet and JavaServer
  Pages technologies. The Java Servlet and JavaServer Pages specifications are
  developed by Sun under the Java Community Process.

Tomcat is developed in an open and participatory environment and
released under the Apache Software License version 2.0. Tomcat is intended
to be a collaboration of the best-of-breed developers from around the world." );
	script_tag( name: "affected", value: "'tomcat' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~9.0.21~1.fc29", rls: "FC29" ) )){
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

