if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702984" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-1419" );
	script_name( "Debian Security Advisory DSA 2984-1 (acpi-support - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-22 00:00:00 +0200 (Tue, 22 Jul 2014)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2984.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "acpi-support on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.140-5+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 0.142-2.

For the unstable distribution (sid), this problem has been fixed in
version 0.142-2.

We recommend that you upgrade your acpi-support packages." );
	script_tag( name: "summary", value: "CESG discovered a root escalation flaw in the acpi-support package. An
unprivileged user can inject the DBUS_SESSION_BUS_ADDRESS environment
variable to run arbitrary commands as root user via the policy-funcs
script." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "acpi-fakekey", ver: "0.140-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "acpi-support", ver: "0.140-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "acpi-support-base", ver: "0.140-5+deb7u1", rls: "DEB7" ) ) != NULL){
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

