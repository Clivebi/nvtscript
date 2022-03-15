if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702670" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-3371", "CVE-2013-3369", "CVE-2013-3374", "CVE-2013-3368", "CVE-2013-3370", "CVE-2013-3372", "CVE-2013-3373" );
	script_name( "Debian Security Advisory DSA 2670-1 (request-tracker3.8 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-22 00:00:00 +0200 (Wed, 22 May 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2670.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "request-tracker3.8 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 3.8.8-7+squeeze7.

The stable, testing and unstable distributions do not contain anymore
request-tracker3.8, which is replaced by request-tracker4.

We recommend that you upgrade your request-tracker3.8 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Request Tracker, an
extensible trouble-ticket tracking system. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2013-3368
The rt command line tool uses semi-predictable temporary files. A
malicious user can use this flaw to overwrite files with permissions
of the user running the rt command line tool.

CVE-2013-3369
A malicious user who is allowed to see administration pages can run
arbitrary Mason components (without control of arguments), which may
have negative side-effects.

CVE-2013-3370
Request Tracker allows direct requests to private callback
components, which could be used to exploit a Request Tracker
extension or a local callback which uses the arguments passed to it
insecurely.

CVE-2013-3371
Request Tracker is vulnerable to cross-site scripting attacks via
attachment filenames.

CVE-2013-3372
Dominic Hargreaves discovered that Request Tracker is vulnerable to
an HTTP header injection limited to the value of the
Content-Disposition header.

CVE-2013-3373
Request Tracker is vulnerable to a MIME header injection in outgoing
email generated by Request Tracker.

Request Tracker stock templates are resolved by this update. But any
custom email templates should be updated to ensure that values
interpolated into mail headers do not contain newlines.

CVE-2013-3374
Request Tracker is vulnerable to limited session re-use when using
the file-based session store, Apache::Session::File. However Request
Tracker's default session configuration only uses
Apache::Session::File when configured for Oracle databases.

This version of Request Tracker includes a database content upgrade. If
you are using a dbconfig-managed database, you will be offered the
choice of applying this automatically. Otherwise see the explanation in
/usr/share/doc/request-tracker3.8/NEWS.Debian.gz for the manual steps to
perform.

Please note that if you run request-tracker3.8 under the Apache web
server, you must stop and start Apache manually. The restart
mechanism
is not recommended, especially when using mod_perl or any form of
persistent Perl process such as FastCGI or SpeedyCGI." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "request-tracker3.8", ver: "3.8.8-7+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-apache2", ver: "3.8.8-7+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-clients", ver: "3.8.8-7+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-db-mysql", ver: "3.8.8-7+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-db-postgresql", ver: "3.8.8-7+squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rt3.8-db-sqlite", ver: "3.8.8-7+squeeze7", rls: "DEB6" ) ) != NULL){
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

