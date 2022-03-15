if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704215" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2017-5662", "CVE-2018-8013" );
	script_name( "Debian Security Advisory DSA 4215-1 (batik - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-02 00:00:00 +0200 (Sat, 02 Jun 2018)" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4215.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "batik on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1.7+dfsg-5+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 1.8-4+deb9u1.

We recommend that you upgrade your batik packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/batik" );
	script_tag( name: "summary", value: "Man Yue Mo, Lars Krapf and Pierre Ernst discovered that Batik, a
toolkit for processing SVG images, did not properly validate its
input. This would allow an attacker to cause a denial-of-service,
mount cross-site scripting attacks, or access restricted files on the
server." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libbatik-java", ver: "1.8-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbatik-java", ver: "1.7+dfsg-5+deb8u1", rls: "DEB8" ) )){
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

