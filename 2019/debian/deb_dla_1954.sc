if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891954" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-0193" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-18 16:15:00 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-10-11 02:00:10 +0000 (Fri, 11 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for lucene-solr (DLA-1954-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1954-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lucene-solr'
  package(s) announced via the DLA-1954-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A security vulnerability was discovered in lucene-solr, an enterprise
search server.

The DataImportHandler, an optional but popular module to pull in data
from databases and other sources, has a feature in which the whole DIH
configuration can come from a request's 'dataConfig' parameter. The
debug mode of the DIH admin screen uses this to allow convenient
debugging / development of a DIH config. Since a DIH config can contain
scripts, this parameter is a security risk. Starting from now on, use
of this parameter requires setting the Java System property
'enable.dih.dataConfigParam' to true. For example this can be achieved
with solr-tomcat by adding -Denable.dih.dataConfigParam=true to
JAVA_OPTS in /etc/default/tomcat7." );
	script_tag( name: "affected", value: "'lucene-solr' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.6.2+dfsg-5+deb8u3.

We recommend that you upgrade your lucene-solr packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-contrib-java", ver: "3.6.2+dfsg-5+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java", ver: "3.6.2+dfsg-5+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblucene3-java-doc", ver: "3.6.2+dfsg-5+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsolr-java", ver: "3.6.2+dfsg-5+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-common", ver: "3.6.2+dfsg-5+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-jetty", ver: "3.6.2+dfsg-5+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "solr-tomcat", ver: "3.6.2+dfsg-5+deb8u3", rls: "DEB8" ) )){
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

