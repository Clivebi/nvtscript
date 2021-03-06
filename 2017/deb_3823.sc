if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703823" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-6964" );
	script_name( "Debian Security Advisory DSA 3823-1 (eject - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-28 00:00:00 +0200 (Tue, 28 Mar 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3823.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "eject on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2.1.5+deb1+cvs20081104-13.1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.1.5+deb1+cvs20081104-13.2.

We recommend that you upgrade your eject packages." );
	script_tag( name: "summary", value: "Ilja Van Sprundel discovered that the dmcrypt-get-device helper used to
check if a given device is an encrypted device handled by devmapper, and
used in eject, does not check return values from setuid() and setgid()
when dropping privileges." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "eject", ver: "2.1.5+deb1+cvs20081104-13.1+deb8u1", rls: "DEB8" ) ) != NULL){
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

