if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704227" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-1002200" );
	script_name( "Debian Security Advisory DSA 4227-1 (plexus-archiver - security update)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-12 00:00:00 +0200 (Tue, 12 Jun 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:32:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4227.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "plexus-archiver on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.2-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 2.2-1+deb9u1.

We recommend that you upgrade your plexus-archiver packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/plexus-archiver" );
	script_tag( name: "summary", value: "Danny Grander discovered a directory traversal flaw in plexus-archiver,
an Archiver plugin for the Plexus compiler system, allowing an attacker
to overwrite any file writable by the extracting user via a specially
crafted Zip archive." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libplexus-archiver-java", ver: "2.2-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libplexus-archiver-java", ver: "1.2-1+deb8u1", rls: "DEB8" ) )){
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

