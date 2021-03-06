if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703546" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2015-7801", "CVE-2016-2191", "CVE-2016-3981", "CVE-2016-3982" );
	script_name( "Debian Security Advisory DSA 3546-1 (optipng - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-07 00:00:00 +0200 (Thu, 07 Apr 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3546.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "optipng on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 0.6.4-1+deb7u2. This update also fixes
CVE-2015-7801, which was originally targeted for a wheezy point update.

For the stable distribution (jessie), this problem has been fixed in
version 0.7.5-1+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your optipng packages." );
	script_tag( name: "summary", value: "Hans Jerry Illikainen discovered that
missing input sanitising in the BMP processing code of the optipng PNG optimiser
may result in denial of service or the execution of arbitrary code if a malformed
file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "optipng", ver: "0.6.4-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "optipng", ver: "0.7.5-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

