if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703845" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-8779" );
	script_name( "Debian Security Advisory DSA 3845-1 (libtirpc - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-08 00:00:00 +0200 (Mon, 08 May 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3845.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libtirpc on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 0.2.5-1+deb8u1 of libtirpc and version 0.2.1-6+deb8u2 of rpcbind.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 0.2.5-1.2 and version 0.2.3-0.6 of rpcbind.

For the unstable distribution (sid), this problem has been fixed in
version 0.2.5-1.2 and version 0.2.3-0.6 of rpcbind.

We recommend that you upgrade your libtirpc packages." );
	script_tag( name: "summary", value: "Guido Vranken discovered that incorrect memory management in libtirpc,
a transport-independent RPC library used by rpcbind and other programs
may result in denial of service via memory exhaustion (depending on
memory management settings)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rpcbind", ver: "0.2.3-0.6", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rpcbind", ver: "0.2.1-6+deb8u2", rls: "DEB8" ) ) != NULL){
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

