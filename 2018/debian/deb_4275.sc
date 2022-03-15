if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704275" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-14432" );
	script_name( "Debian Security Advisory DSA 4275-1 (keystone - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-16 00:00:00 +0200 (Thu, 16 Aug 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 16:13:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4275.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "keystone on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 2:10.0.0-9+deb9u1.

We recommend that you upgrade your keystone packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/keystone" );
	script_tag( name: "summary", value: "Kristi Nikolla discovered an information leak in Keystone, the OpenStack
identity service, if running in a federated setup." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "keystone", ver: "2:10.0.0-9+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "keystone-doc", ver: "2:10.0.0-9+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-keystone", ver: "2:10.0.0-9+deb9u1", rls: "DEB9" ) )){
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

