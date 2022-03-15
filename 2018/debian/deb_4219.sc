if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704219" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079" );
	script_name( "Debian Security Advisory DSA 4219-1 (jruby - security update)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-08 00:00:00 +0200 (Fri, 08 Jun 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-20 13:29:00 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4219.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "jruby on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1.7.26-1+deb9u1.

We recommend that you upgrade your jruby packages.

In addition, this message serves as an announcement that security
support for jruby in the Debian 8 oldstable release (jessie) is now
discontinued.

Users of jruby in Debian 8 that want security updates are strongly
encouraged to upgrade now to the current Debian 9 stable release
(stretch)." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/jruby" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in jruby, a Java
implementation of the Ruby programming language. They would allow an
attacker to use specially crafted gem files to mount cross-site
scripting attacks, cause denial of service through an infinite loop,
write arbitrary files, or run malicious code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "jruby", ver: "1.7.26-1+deb9u1", rls: "DEB9" ) )){
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
