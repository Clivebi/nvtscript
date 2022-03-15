if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703915" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-1000026" );
	script_name( "Debian Security Advisory DSA 3915-1 (ruby-mixlib-archive - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-20 00:00:00 +0200 (Thu, 20 Jul 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-30 17:34:00 +0000 (Fri, 30 Apr 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3915.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "ruby-mixlib-archive on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 0.2.0-1+deb9u1.

We recommend that you upgrade your ruby-mixlib-archive packages." );
	script_tag( name: "summary", value: "It was discovered that ruby-mixlib-archive, a Chef Software's library
used to handle various archive formats, was vulnerable to a directory
traversal attack. This allowed attackers to overwrite arbitrary files
by using a malicious tar archive containing '..' in its entries." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ruby-mixlib-archive", ver: "0.2.0-1+deb9u1", rls: "DEB9" ) ) != NULL){
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

