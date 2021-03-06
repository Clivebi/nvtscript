if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704452" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-11307", "CVE-2018-12022", "CVE-2018-12023", "CVE-2018-14718", "CVE-2018-14719", "CVE-2018-14720", "CVE-2018-14721", "CVE-2018-19360", "CVE-2018-19361", "CVE-2018-19362", "CVE-2019-12086" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 21:47:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-05-26 02:00:15 +0000 (Sun, 26 May 2019)" );
	script_name( "Debian Security Advisory DSA 4452-1 (jackson-databind - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4452.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4452-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the DSA-4452-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues were found in jackson-databind, a Java library
to parse JSON and other data formats which could result in information
disclosure or the execution of arbitrary code." );
	script_tag( name: "affected", value: "'jackson-databind' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 2.8.6-1+deb9u5.

We recommend that you upgrade your jackson-databind packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java", ver: "2.8.6-1+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java-doc", ver: "2.8.6-1+deb9u5", rls: "DEB9" ) )){
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

