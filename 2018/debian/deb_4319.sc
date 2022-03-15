if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704319" );
	script_version( "2021-06-17T11:57:04+0000" );
	script_cve_id( "CVE-2018-10873" );
	script_name( "Debian Security Advisory DSA 4319-1 (spice - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:57:04 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-15 00:00:00 +0200 (Mon, 15 Oct 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4319.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "spice on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 0.12.8-2.1+deb9u2.

We recommend that you upgrade your spice packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/spice" );
	script_tag( name: "summary", value: "Frediano Ziglio reported a missing check in the script to generate
demarshalling code in the SPICE protocol client and server library. The
generated demarshalling code is prone to multiple buffer overflows. An
authenticated attacker can take advantage of this flaw to cause a denial
of service (spice server crash), or possibly, execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libspice-server-dev", ver: "0.12.8-2.1+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspice-server1", ver: "0.12.8-2.1+deb9u2", rls: "DEB9" ) )){
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

