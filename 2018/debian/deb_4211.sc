if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704211" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2017-18266" );
	script_name( "Debian Security Advisory DSA 4211-1 (xdg-utils - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-25 00:00:00 +0200 (Fri, 25 May 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-14 13:33:00 +0000 (Thu, 14 Jun 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4211.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "xdg-utils on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.1.0~rc1+git20111210-7.4+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.1.1-1+deb9u1.

We recommend that you upgrade your xdg-utils packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/xdg-utils" );
	script_tag( name: "summary", value: "Gabriel Corona discovered that xdg-utils, a set of tools for desktop
environment integration, is vulnerable to argument injection attacks. If
the environment variable BROWSER in the victim host has a '%s' and the
victim opens a link crafted by an attacker with xdg-open, the malicious
party could manipulate the parameters used by the browser when opened.
This manipulation could set, for example, a proxy to which the network
traffic could be intercepted for that particular execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "xdg-utils", ver: "1.1.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xdg-utils", ver: "1.1.0~rc1+git20111210-7.4+deb8u1", rls: "DEB8" ) )){
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

