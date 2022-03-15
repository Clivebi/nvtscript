if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891798" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-12086" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-05-22 02:00:06 +0000 (Wed, 22 May 2019)" );
	script_name( "Debian LTS: Security Advisory for jackson-databind (DLA-1798-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1798-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/929177" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the DLA-1798-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A Polymorphic Typing issue was discovered in jackson-databind, a JSON
library for Java. When Default Typing is enabled (either globally or
for a specific property) for an externally exposed JSON endpoint, the
service has the mysql-connector-java jar (8.0.14 or earlier) in the
classpath, and an attacker can host a crafted MySQL server reachable
by the victim, an attacker can send a crafted JSON message that allows
them to read arbitrary local files on the server. This occurs because of
missing com.mysql.cj.jdbc.admin.MiniAdmin validation." );
	script_tag( name: "affected", value: "'jackson-databind' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.4.2-2+deb8u6.

We recommend that you upgrade your jackson-databind packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java", ver: "2.4.2-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java-doc", ver: "2.4.2-2+deb8u6", rls: "DEB8" ) )){
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

