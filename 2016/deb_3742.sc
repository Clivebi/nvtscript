if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703742" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-9956" );
	script_name( "Debian Security Advisory DSA 3742-1 (flightgear - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-20 00:00:00 +0100 (Tue, 20 Dec 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3742.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "flightgear on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 3.0.0-5+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1:2016.4.3+dfsg-1.

We recommend that you upgrade your flightgear packages." );
	script_tag( name: "summary", value: "It was discovered that the Flight Gear
flight simulator performs insufficient sanitising of Nasal scripts which allows a
malicious script to overwrite arbitrary files with the privileges of the user
running Flight Gear." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "flightgear", ver: "3.0.0-5+deb8u1", rls: "DEB8" ) ) != NULL){
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

