if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69114" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_cve_id( "CVE-2011-0434", "CVE-2011-0435", "CVE-2011-0436", "CVE-2011-0437" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2179-1 (dtc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_tag( name: "insight", value: "Ansgar Burchardt discovered several vulnerabilities in DTC, a web
control panel for admin and accounting hosting services.

CVE-2011-0434
The bw_per_moth.php graph contains an SQL injection vulnerability.

CVE-2011-0435
Insufficient checks in bw_per_month.php can lead to bandwidth
usage information disclosure.

CVE-2011-0436
After a registration, passwords are sent in cleartext
email messages.

CVE-2011-0437
Authenticated users could delete accounts using an obsolete
interface which was incorrectly included in the package.

This update introduces a new configuration option which controls the
presence of cleartext passwords in email messages.  The default is not
to include cleartext passwords" );
	script_tag( name: "summary", value: "The remote host is missing an update to dtc
announced via advisory DSA 2179-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 0.29.17-1+lenny1.

The stable distribution (squeeze) and the testing distribution
(wheezy) do not contain any dtc packages.

For the unstable distribution (sid), this problem has been fixed in
version 0.32.10-1.

We recommend that you upgrade your dtc packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202179-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dtc-common", ver: "0.29.17-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dtc-core", ver: "0.29.17-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dtc-cyrus", ver: "0.29.17-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dtc-postfix-courier", ver: "0.29.17-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dtc-stats-daemon", ver: "0.29.17-1+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dtc-toaster", ver: "0.29.17-1+lenny1", rls: "DEB5" ) ) != NULL){
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

