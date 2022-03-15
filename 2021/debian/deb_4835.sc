if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704835" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-13943", "CVE-2020-17527" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-01-24 04:00:10 +0000 (Sun, 24 Jan 2021)" );
	script_name( "Debian: Security Advisory for tomcat9 (DSA-4835-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4835.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4835-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat9'
  package(s) announced via the DSA-4835-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in the Tomcat servlet and JSP
engine, which could result in information disclosure." );
	script_tag( name: "affected", value: "'tomcat9' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 9.0.31-1~deb10u3.

We recommend that you upgrade your tomcat9 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtomcat9-embed-java", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat9-java", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat9", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat9-admin", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat9-common", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat9-docs", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat9-examples", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat9-user", ver: "9.0.31-1~deb10u3", rls: "DEB10" ) )){
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

