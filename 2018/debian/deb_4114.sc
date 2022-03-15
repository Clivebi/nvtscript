if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704114" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2017-17485", "CVE-2018-5968" );
	script_name( "Debian Security Advisory DSA 4114-1 (jackson-databind - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-15 00:00:00 +0100 (Thu, 15 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-19 15:51:00 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4114.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "jackson-databind on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.4.2-2+deb8u3.

For the stable distribution (stretch), these problems have been fixed in
version 2.8.6-1+deb9u3.

We recommend that you upgrade your jackson-databind packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/jackson-databind" );
	script_tag( name: "summary", value: "It was discovered that jackson-databind, a Java library used to parse
JSON and other data formats, did not properly validate user input
before attempting deserialization. This allowed an attacker to perform
code execution by providing maliciously crafted input." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java", ver: "2.4.2-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java-doc", ver: "2.4.2-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java", ver: "2.8.6-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjackson2-databind-java-doc", ver: "2.8.6-1+deb9u3", rls: "DEB9" ) )){
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

