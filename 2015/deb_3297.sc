if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703297" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1330" );
	script_name( "Debian Security Advisory DSA 3297-1 (unattended-upgrades - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-29 00:00:00 +0200 (Mon, 29 Jun 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3297.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "unattended-upgrades on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 0.79.5+wheezy2.

For the stable distribution (jessie), this problem has been fixed in
version 0.83.3.2+deb8u1.

For the unstable distribution (sid), this problem will be fixed shortly.

We recommend that you upgrade your unattended-upgrades packages." );
	script_tag( name: "summary", value: "It was discovered that unattended-upgrades,
a script for automatic installation of security upgrades, did not properly authenticate
downloaded packages when the force-confold or force-confnew dpkg options
were enabled via the DPkg::Options::* apt configuration." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "unattended-upgrades", ver: "0.79.5+wheezy2", rls: "DEB7" ) ) != NULL){
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

