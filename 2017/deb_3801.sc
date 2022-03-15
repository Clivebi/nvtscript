if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703801" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-5946" );
	script_name( "Debian Security Advisory DSA 3801-1 (ruby-zip - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-04 00:00:00 +0100 (Sat, 04 Mar 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-14 12:47:00 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3801.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "ruby-zip on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 1.1.6-1+deb8u1.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 1.2.0-1.1.

For the unstable distribution (sid), this problem has been fixed in
version 1.2.0-1.1.

We recommend that you upgrade your ruby-zip packages." );
	script_tag( name: "summary", value: "It was discovered that ruby-zip, a Ruby module for reading and writing
zip files, is prone to a directory traversal vulnerability. An attacker
can take advantage of this flaw to overwrite arbitrary files during
archive extraction via a .. (dot dot) in an extracted filename." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ruby-zip", ver: "1.2.0-1.1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-zip", ver: "1.1.6-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

